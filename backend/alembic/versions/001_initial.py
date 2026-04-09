"""Initial database schema for PhishNet.

Revision ID: 001_initial
Revises:
Create Date: 2026-03-01 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # =========================================================================
    # Users table
    # =========================================================================
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True, index=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "role",
            sa.String(50),
            nullable=False,
            server_default="analyst",
        ),
        sa.Column("api_key", sa.String(255), nullable=True, unique=True),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # =========================================================================
    # URL Scans table
    # =========================================================================
    op.create_table(
        "url_scans",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id", sa.String(36), nullable=False, unique=True, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("final_url", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True, index=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
            index=True,
        ),
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column(
            "rf_score", sa.Float(), nullable=True, comment="Random Forest score"
        ),
        sa.Column(
            "gb_score", sa.Float(), nullable=True, comment="Gradient Boosting score"
        ),
        sa.Column("bert_score", sa.Float(), nullable=True, comment="BERT model score"),
        sa.Column("features", postgresql.JSONB(), nullable=True),
        sa.Column("redirect_chain", postgresql.JSONB(), nullable=True),
        sa.Column("screenshot_path", sa.String(500), nullable=True),
        sa.Column("scan_duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("source", sa.String(50), server_default="api"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_url_scans_created_at", "url_scans", ["created_at"])
    op.create_index("ix_url_scans_verdict", "url_scans", ["verdict"])

    # =========================================================================
    # URL Feature Records table
    # =========================================================================
    op.create_table(
        "url_feature_records",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("url_scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url_length", sa.Integer(), nullable=True),
        sa.Column("domain_length", sa.Integer(), nullable=True),
        sa.Column("path_length", sa.Integer(), nullable=True),
        sa.Column("subdomain_count", sa.Integer(), nullable=True),
        sa.Column("digit_ratio", sa.Float(), nullable=True),
        sa.Column("special_char_ratio", sa.Float(), nullable=True),
        sa.Column("entropy", sa.Float(), nullable=True),
        sa.Column("has_ip_address", sa.Boolean(), nullable=True),
        sa.Column("is_punycode", sa.Boolean(), nullable=True),
        sa.Column("tld_category", sa.String(50), nullable=True),
        sa.Column("domain_age_days", sa.Integer(), nullable=True),
        sa.Column("has_whois_privacy", sa.Boolean(), nullable=True),
        sa.Column("registrar", sa.String(255), nullable=True),
        sa.Column("ssl_valid", sa.Boolean(), nullable=True),
        sa.Column("ssl_issuer", sa.String(255), nullable=True),
        sa.Column("ssl_days_remaining", sa.Integer(), nullable=True),
        sa.Column("page_title_match", sa.Float(), nullable=True),
        sa.Column("has_login_form", sa.Boolean(), nullable=True),
        sa.Column("external_resource_ratio", sa.Float(), nullable=True),
        sa.Column("brand_similarity_score", sa.Float(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # =========================================================================
    # Email Scans table
    # =========================================================================
    op.create_table(
        "email_scans",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id", sa.String(36), nullable=False, unique=True, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("sender", sa.String(255), nullable=True, index=True),
        sa.Column("sender_domain", sa.String(255), nullable=True),
        sa.Column("recipient", sa.String(255), nullable=True),
        sa.Column("body_text", sa.Text(), nullable=True),
        sa.Column("body_html", sa.Text(), nullable=True),
        sa.Column("raw_headers", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column("spf_result", sa.String(20), nullable=True),
        sa.Column("dkim_result", sa.String(20), nullable=True),
        sa.Column("dmarc_result", sa.String(20), nullable=True),
        sa.Column("urgency_score", sa.Float(), nullable=True),
        sa.Column("brand_impersonation_score", sa.Float(), nullable=True),
        sa.Column("link_count", sa.Integer(), nullable=True),
        sa.Column("suspicious_link_count", sa.Integer(), nullable=True),
        sa.Column("extracted_urls", postgresql.JSONB(), nullable=True),
        sa.Column("features", postgresql.JSONB(), nullable=True),
        sa.Column("scan_duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # =========================================================================
    # Email Attachments table
    # =========================================================================
    op.create_table(
        "email_attachments",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column(
            "email_scan_id",
            sa.Integer(),
            sa.ForeignKey("email_scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(100), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("file_hash_sha256", sa.String(64), nullable=True),
        sa.Column("is_suspicious", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("has_macros", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("analysis_result", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # =========================================================================
    # Threat Indicators table
    # =========================================================================
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column(
            "indicator_type",
            sa.String(50),
            nullable=False,
            index=True,
        ),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("value_hash", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("threat_type", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("source", sa.String(100), nullable=True),
        sa.Column("feed_id", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("metadata_", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # =========================================================================
    # Threat Feeds table
    # =========================================================================
    op.create_table(
        "threat_feeds",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("feed_type", sa.String(50), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("refresh_interval_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("last_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("indicator_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("auth_config", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # =========================================================================
    # Whitelist Entries table
    # =========================================================================
    op.create_table(
        "whitelist_entries",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("domain", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column(
            "entry_type",
            sa.String(50),
            nullable=False,
            server_default="manual",
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("added_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("whitelist_entries")
    op.drop_table("threat_feeds")
    op.drop_table("threat_indicators")
    op.drop_table("email_attachments")
    op.drop_table("email_scans")
    op.drop_table("url_feature_records")
    op.drop_index("ix_url_scans_verdict", table_name="url_scans")
    op.drop_index("ix_url_scans_created_at", table_name="url_scans")
    op.drop_table("url_scans")
    op.drop_table("users")
