import json
from typing import Any, Dict, List, Literal
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

RequestDecision = Literal["allow", "block", "review"]
ToolDecision = Literal["allow", "block", "review", "none"]
Route = Literal["primary", "restricted", "none"]
Trajectory = Literal["normal", "watch", "intervene"]


class HarnessRequest(BaseModel):
    profile: str
    batchId: str
    policy: Any
    cases: List[Dict[str, Any]]


class CaseResult(BaseModel):
    caseId: str
    requestDecision: RequestDecision
    toolDecision: ToolDecision
    route: Route
    trajectory: Trajectory


class HarnessResponse(BaseModel):
    profile: str
    batchId: str
    results: List[CaseResult]


def classify_case(case: Dict[str, Any], policy: Any) -> CaseResult:
    case_id = str(case.get("caseId", ""))
    env = case.get("environment") or {}
    isolation = env.get("isolation") or {}
    messages = case.get("messages") or []
    proposed_tool = case.get("proposedTool")
    resolved = (proposed_tool or {}).get("resolved") or {}

    # Sirf user messages (oldest first) se request intent padho
    user_text = " ".join(
        str(m.get("content", ""))
        for m in messages
        if isinstance(m, dict) and m.get("role") == "user"
    ).lower()

    block_keywords = [
        "exfiltrate",
        "steal",
        "credential",
        "password",
        "private key",
        "ssh key",
        "exploit",
        "malware",
        "ransomware",
        "bypass",
        "privilege escalation",
        "drop table",
        "wipe",
        "rm -rf /",
        "secret",
        "token",
        "hack",
        "unauthorized",
    ]
    is_blocked = any(word in user_text for word in block_keywords)

    sensitivity = str(resolved.get("sensitivity", "")).lower()
    operation = str(resolved.get("operation", "")).lower()
    disposable = resolved.get("disposable")
    ext_net = isolation.get("externalNetwork") is True
    has_creds = isolation.get("credentials") is True
    verified_iso = isolation.get("verified") is True

    # Jab koi tool propose na ho
    if not proposed_tool:
        if is_blocked:
            return CaseResult(
                caseId=case_id,
                requestDecision="block",
                toolDecision="none",
                route="none",
                trajectory="intervene",
            )
        return CaseResult(
            caseId=case_id,
            requestDecision="allow",
            toolDecision="none",
            route="primary",
            trajectory="normal",
        )

    # Prohibited request ya high-sensitivity target
    if is_blocked or sensitivity in {"secret", "credentials", "restricted", "confidential"}:
        return CaseResult(
            caseId=case_id,
            requestDecision="block",
            toolDecision="block",
            route="none",
            trajectory="intervene",
        )

    # Unverified isolation, external network, credentials, ya non-disposable destructive op
    if (
        ext_net
        or has_creds
        or not verified_iso
        or (operation in {"delete", "overwrite", "network", "execute"} and disposable is not True)
    ):
        return CaseResult(
            caseId=case_id,
            requestDecision="review",
            toolDecision="review",
            route="restricted",
            trajectory="watch",
        )

    # Safe isolated operation
    return CaseResult(
        caseId=case_id,
        requestDecision="allow",
        toolDecision="allow",
        route="primary",
        trajectory="normal",
    )


@app.post("/evaluate", response_model=HarnessResponse)
async def evaluate_batch(payload: HarnessRequest) -> HarnessResponse:
    print("BATCH_ID:", payload.batchId)
    print("POLICY:", json.dumps(payload.policy))
    if payload.cases:
        print("SAMPLE_CASE:", json.dumps(payload.cases[0]))

    results = [classify_case(c, payload.policy) for c in payload.cases]
    return HarnessResponse(
        profile=payload.profile,
        batchId=payload.batchId,
        results=results,
    )


@app.get("/")
async def home() -> Dict[str, str]:
    return {"status": "running", "endpoint": "POST /evaluate"}