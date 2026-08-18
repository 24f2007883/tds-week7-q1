from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import re

app = FastAPI()

class WorkflowAction(BaseModel):
    owner: str
    name: str
    ref: str

class Workflow(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[Dict[str, Any]]
    environmentApproval: Optional[bool] = None

class Image(BaseModel):
    multistage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool

class ReleaseGatePayload(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image

@app.post("/release-gate")
def check_release_gate(payload: ReleaseGatePayload):
    violations = []

    # Rule 1: Least Privilege Permissions
    # Allowed exact scopes: contents: read, packages: write, id-token: none
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }
    
    # Check for excess/missing/mismatched permissions
    if payload.workflow.permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # Rule 2: Pull Request Trigger & Test Execution
    # If event is pull_request (or trigger uses pull_request_target), check unsafe PR trigger
    if payload.workflow.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    
    # Tests must pass, matrix complete, failFast must be False
    if not (payload.workflow.testsPassed and payload.workflow.matrixComplete and not payload.workflow.failFast):
        violations.append("TESTS_INCOMPLETE")

    # Rule 3: Action Pinning
    # Actions owned by 'actions' may use version tag (e.g. v4).
    # Third-party actions (owner != 'actions') must be pinned to full 40-char lowercase hex commit SHA.
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")
    for act in payload.workflow.actions:
        owner = act.get("owner", "")
        ref = act.get("ref", "")
        if owner != "actions":
            if not sha_pattern.match(ref):
                violations.append("MUTABLE_ACTION")
                break

    # Rule 4: Container Image Security Rules
    if not payload.image.multistage:
        violations.append("SINGLE_STAGE_IMAGE")

    if payload.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    # secretMode must be either "none" or "buildkit"
    if payload.image.secretMode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    if payload.image.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    if not payload.image.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # Rule 5: Production Target Rules
    if payload.target == "production":
        invalid_ref = (payload.event != "push" or payload.ref != "refs/heads/main")
        if invalid_ref:
            violations.append("INVALID_PRODUCTION_REF")
            
        if payload.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    # Return decision
    decision = "promote" if len(violations) == 0 else "block"
    return {
        "decision": decision,
        "violations": violations
    }