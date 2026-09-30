-- P2a language ecosystems (DOMAIN_MODEL.md §2.3 "As built (P2a, language
-- ecosystems)"): several ranges of one package may start at the same
-- version in one OSV language record (Go: github.com/CosmWasm/wasmvm/v2
-- listed three times from "0", fixed 2.0.6, 2.1.5 and 2.2.2). Keeping
-- only the first, as for a distro's duplicate release names, would miss
-- versions the others cover, so `seq` numbers such rows (0 for the first,
-- and for every distro row) and joins the primary key.

BEGIN;

ALTER TABLE advisory_affected ADD COLUMN seq smallint NOT NULL DEFAULT 0;
ALTER TABLE advisory_affected DROP CONSTRAINT advisory_affected_pkey;
ALTER TABLE advisory_affected
    ADD PRIMARY KEY (advisory_id, distro, release, source_package, channel, introduced, seq);

COMMIT;
