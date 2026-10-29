CREATE TABLE mail_delivery_receipts (
    id UUID PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL,
    sent_at TIMESTAMP WITH TIME ZONE
);
