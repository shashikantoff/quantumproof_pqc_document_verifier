"""Ledger adapters. The FastAPI service never needs Fabric internals directly."""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .database import DevelopmentLedgerRecord


class LedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class LedgerCommit:
    transaction_id: str
    block_number: int | None
    backend: str


class LedgerAdapter(Protocol):
    name: str

    def register(self, payload: dict[str, Any]) -> LedgerCommit: ...

    def revoke(self, document_id: str, reason: str) -> LedgerCommit: ...

    def read(self, document_id: str) -> dict[str, Any] | None: ...

    def history(self, document_id: str) -> list[dict[str, Any]]: ...


class DevelopmentLedger:
    """Persistent local adapter for demos; no consensus or blockchain guarantees."""

    name = "development-ledger"

    def __init__(self, sessions: sessionmaker[Session]):
        self.sessions = sessions

    def register(self, payload: dict[str, Any]) -> LedgerCommit:
        document_id = str(payload["documentId"])
        with self.sessions() as session:
            next_block = int(session.scalar(select(func.coalesce(func.max(DevelopmentLedgerRecord.block_number), 0))) or 0) + 1
            transaction_id = f"dev-{uuid.uuid4()}"
            entry = DevelopmentLedgerRecord(
                document_id=document_id,
                payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
                transaction_id=transaction_id,
                block_number=next_block,
            )
            session.add(entry)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise LedgerError(f"document {document_id} is already registered in the development ledger") from exc
        return LedgerCommit(transaction_id, next_block, self.name)

    def revoke(self, document_id: str, reason: str) -> LedgerCommit:
        with self.sessions() as session:
            entry = session.scalar(select(DevelopmentLedgerRecord).where(DevelopmentLedgerRecord.document_id == document_id))
            if entry is None:
                raise LedgerError(f"document {document_id} is not registered in the development ledger")
            payload = json.loads(entry.payload_json)
            payload["status"] = "REVOKED"
            payload["revocationReason"] = reason
            payload["revokedAt"] = datetime.now(timezone.utc).isoformat()
            transaction_id = f"dev-revoke-{uuid.uuid4()}"
            entry.payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            entry.transaction_id = transaction_id
            session.commit()
        return LedgerCommit(transaction_id, entry.block_number, self.name)

    def read(self, document_id: str) -> dict[str, Any] | None:
        with self.sessions() as session:
            entry = session.scalar(select(DevelopmentLedgerRecord).where(DevelopmentLedgerRecord.document_id == document_id))
            if entry is None:
                return None
            payload = json.loads(entry.payload_json)
            payload["transactionId"] = entry.transaction_id
            payload["blockNumber"] = entry.block_number
            return payload

    def history(self, document_id: str) -> list[dict[str, Any]]:
        entry = self.read(document_id)
        return [] if entry is None else [{"record": entry, "timestamp": datetime.now(timezone.utc).isoformat(), "isDelete": False}]


class FabricGatewayLedger:
    """Calls the optional REST bridge, which uses Fabric's official Node Gateway SDK."""

    name = "hyperledger-fabric"

    def __init__(self, base_url: str | None, token: str | None):
        if not base_url or not token:
            raise LedgerError("FABRIC_GATEWAY_URL and FABRIC_GATEWAY_TOKEN are required for the Fabric ledger backend")
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            with httpx.Client(base_url=self.base_url, headers=self.headers, timeout=12.0) as client:
                response = client.request(method, path, **kwargs)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise LedgerError(f"Fabric gateway request failed: {exc}") from exc

    def register(self, payload: dict[str, Any]) -> LedgerCommit:
        response = self._request("POST", "/records", json=payload)
        if not response:
            raise LedgerError("Fabric gateway returned an empty registration response")
        return LedgerCommit(str(response["transactionId"]), response.get("blockNumber"), self.name)

    def revoke(self, document_id: str, reason: str) -> LedgerCommit:
        response = self._request("POST", f"/records/{document_id}/revoke", json={"reason": reason})
        if not response:
            raise LedgerError("Fabric gateway returned an empty revocation response")
        return LedgerCommit(str(response["transactionId"]), response.get("blockNumber"), self.name)

    def read(self, document_id: str) -> dict[str, Any] | None:
        return self._request("GET", f"/records/{document_id}")

    def history(self, document_id: str) -> list[dict[str, Any]]:
        response = self._request("GET", f"/records/{document_id}/history")
        return response or []


def make_ledger(backend: str, sessions: sessionmaker[Session], fabric_url: str | None, fabric_token: str | None) -> LedgerAdapter:
    if backend == "development":
        return DevelopmentLedger(sessions)
    if backend == "fabric":
        return FabricGatewayLedger(fabric_url, fabric_token)
    raise LedgerError("LEDGER_BACKEND must be 'development' or 'fabric'")
