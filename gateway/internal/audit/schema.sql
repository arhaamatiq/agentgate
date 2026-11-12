-- AgentGate audit log: append-only, hash-chained.
--
-- One chain per Kafka partition (chain_id). The hash covers prev_hash,
-- chain_id, seq and the exact event bytes; the derived columns are for
-- querying and the verifier checks them against the event.

CREATE TABLE IF NOT EXISTS audit_events (
    chain_id     integer     NOT NULL,
    seq          bigint      NOT NULL CHECK (seq > 0),
    kafka_offset bigint      NOT NULL,
    event_id     uuid        NOT NULL,
    ts           timestamptz NOT NULL,
    agent_id     text        NOT NULL,
    session_id   text        NOT NULL,
    tool_name    text        NOT NULL,
    verdict      text        NOT NULL,
    tier         smallint    NOT NULL,
    policy       text        NOT NULL,
    fail_closed  boolean     NOT NULL,
    event        text        NOT NULL,
    prev_hash    bytea       NOT NULL,
    hash         bytea       NOT NULL,
    ingested_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, seq),
    UNIQUE (event_id),
    UNIQUE (chain_id, kafka_offset)
);

CREATE INDEX IF NOT EXISTS audit_events_agent_ts ON audit_events (agent_id, ts);
CREATE INDEX IF NOT EXISTS audit_events_blocked_ts ON audit_events (ts) WHERE verdict = 'block';

CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % rejected', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
