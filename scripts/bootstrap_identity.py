from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from n09_admin.audit import AuditEvent  # noqa: E402
from n09_admin.domain import Identity, IdentityStatus  # noqa: E402
from n09_admin.federated_identity import ExternalIdentityLinkRequest  # noqa: E402
from n09_admin.persistence import SQLiteRepository  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Amorce une identité NSK et son premier rattachement audité."
    )
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--identity-id", required=True, type=UUID)
    parser.add_argument("--email", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--justification", required=True)
    args = parser.parse_args()

    args.database.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    correlation_id = uuid4()
    identity = Identity(
        identity_id=args.identity_id,
        email=args.email,
        display_name=args.display_name,
        status=IdentityStatus.ACTIVE,
    )

    with SQLiteRepository(args.database) as repository:
        existing_link = repository.find_external_identity(args.issuer, args.subject)
        if existing_link is not None:
            if existing_link.identity_id != identity.identity_id:
                raise SystemExit("Le sujet externe appartient déjà à une autre identité.")
            print(f"Rattachement déjà présent pour {identity.identity_id}")
            return

        existing_identity = repository.get_identity(identity.identity_id)
        if existing_identity is None:
            repository.save_identity(
                identity,
                AuditEvent(
                    correlation_id=correlation_id,
                    actor_id=identity.identity_id,
                    subject_id=identity.identity_id,
                    action="identity.bootstrapped",
                    result="success",
                    source="bootstrap-cli",
                    new_value={"status": IdentityStatus.ACTIVE.value},
                    justification=args.justification,
                ),
            )

        request = ExternalIdentityLinkRequest(
            issuer=args.issuer,
            subject=args.subject,
            provider_key=args.provider,
            email_hint=args.email,
            display_name_hint=args.display_name,
            requested_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        repository.save_link_request(
            request,
            AuditEvent(
                correlation_id=correlation_id,
                actor_id=identity.identity_id,
                action="external_identity.link_requested",
                result="pending",
                source="bootstrap-cli",
                new_value={"request_id": str(request.request_id)},
                justification=args.justification,
            ),
        )
        repository.approve_link_request(
            request.request_id,
            identity.identity_id,
            identity.identity_id,
            args.justification,
            AuditEvent(
                correlation_id=correlation_id,
                actor_id=identity.identity_id,
                subject_id=identity.identity_id,
                action="external_identity.link_approved",
                result="success",
                source="bootstrap-cli",
                previous_value={"status": "pending"},
                new_value={"status": "approved"},
                justification=args.justification,
            ),
            now=now,
        )
        if not repository.verify_audit_chain():
            raise SystemExit("La chaîne d’audit n’est pas valide.")
        print(f"Identité NSK créée et rattachée : {identity.identity_id}")


if __name__ == "__main__":
    main()
