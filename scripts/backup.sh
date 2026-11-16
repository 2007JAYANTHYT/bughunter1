#!/bin/bash
# =============================================================================
# BUG HUNTER AGENT - BACKUP SCRIPT
# Run this script to backup database and evidence files
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="$PROJECT_ROOT/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_FILE="$PROJECT_ROOT/bug_hunter.db"
EVIDENCE_DIR="$PROJECT_ROOT/evidence"
CONFIG_DIR="$PROJECT_ROOT/config"

# Create backup directory
mkdir -p "$BACKUP_DIR"

log_info "Starting backup at $(date)"
log_info "Project root: $PROJECT_ROOT"
log_info "Backup directory: $BACKUP_DIR"

# Backup database
if [[ -f "$DB_FILE" ]]; then
    log_info "Backing up database..."
    sqlite3 "$DB_FILE" ".backup $BACKUP_DIR/bug_hunter_$DATE.db"
    if [[ $? -eq 0 ]]; then
        log_success "Database backed up to bug_hunter_$DATE.db"
    else
        log_error "Database backup failed"
        exit 1
    fi
else
    log_warn "Database file not found: $DB_FILE"
fi

# Backup evidence (compress to save space)
if [[ -d "$EVIDENCE_DIR" ]] && [[ -n "$(ls -A $EVIDENCE_DIR)" ]]; then
    log_info "Backing up evidence files..."
    tar -czf "$BACKUP_DIR/evidence_$DATE.tar.gz" -C "$PROJECT_ROOT" evidence/
    if [[ $? -eq 0 ]]; then
        log_success "Evidence backed up to evidence_$DATE.tar.gz"
    else
        log_error "Evidence backup failed"
        exit 1
    fi
else
    log_info "No evidence files to backup"
fi

# Backup configuration
if [[ -d "$CONFIG_DIR" ]]; then
    log_info "Backing up configuration..."
    tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" -C "$PROJECT_ROOT" config/
    if [[ $? -eq 0 ]]; then
        log_success "Configuration backed up to config_$DATE.tar.gz"
    else
        log_error "Configuration backup failed"
        exit 1
    fi
fi

# Create backup manifest
cat > "$BACKUP_DIR/manifest_$DATE.json" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "date": "$DATE",
  "database": "bug_hunter_$DATE.db",
  "evidence": "evidence_$DATE.tar.gz",
  "config": "config_$DATE.tar.gz",
  "project_root": "$PROJECT_ROOT",
  "version": "1.0.0"
}
EOF

log_success "Backup manifest created: manifest_$DATE.json"

# Cleanup old backups (keep last 30 days)
log_info "Cleaning up backups older than 30 days..."
find "$BACKUP_DIR" -name "bug_hunter_*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "evidence_*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "config_*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "manifest_*.json" -mtime +30 -delete

# Optional: Upload to cloud storage
if [[ -n "${RCLONE_REMOTE:-}" ]]; then
    log_info "Uploading to cloud storage..."
    rclone copy "$BACKUP_DIR" "$RCLONE_REMOTE/bug-hunter-backups/" --include "*_$DATE.*"
    if [[ $? -eq 0 ]]; then
        log_success "Backup uploaded to cloud storage"
    else
        log_warn "Cloud upload failed"
    fi
fi

log_success "Backup completed at $(date)"
log_info "Backup files:"
ls -lh "$BACKUP_DIR"/*_$DATE.*

# Print summary
DB_SIZE=$(stat -c%s "$BACKUP_DIR/bug_hunter_$DATE.db" 2>/dev/null || echo 0)
EVIDENCE_SIZE=$(stat -c%s "$BACKUP_DIR/evidence_$DATE.tar.gz" 2>/dev/null || echo 0)
CONFIG_SIZE=$(stat -c%s "$BACKUP_DIR/config_$DATE.tar.gz" 2>/dev/null || echo 0)

log_info "Backup Summary:"
log_info "  Database: $(numfmt --to=iec $DB_SIZE)"
log_info "  Evidence: $(numfmt --to=iec $EVIDENCE_SIZE)"
log_info "  Config: $(numfmt --to=iec $CONFIG_SIZE)"
log_info "  Total: $(numfmt --to=iec $((DB_SIZE + EVIDENCE_SIZE + CONFIG_SIZE)))"