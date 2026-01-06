"""
SQLite database manager for persistent storage.
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from ipaddress import IPv4Address, IPv6Address


class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


class DatabaseManager:
    """Manages SQLite database operations for scan results."""

    # Database schema version for migration support
    SCHEMA_VERSION = 1

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database manager.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or Path("ip_analysis.db")
        self.connection = None
        self.logger = logging.getLogger(__name__)

    def _get_schema_version(self) -> int:
        """Get current database schema version."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA user_version")
                return cursor.fetchone()[0]
        except sqlite3.Error:
            return 0

    def _set_schema_version(self, version: int) -> None:
        """Set database schema version."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"PRAGMA user_version = {version}")
                conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to set schema version: {e}")

    def _validate_database_integrity(self) -> bool:
        """
        Validate database integrity and schema.
        
        Returns:
            True if database is valid, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check database integrity
                cursor.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()[0]
                if integrity_result != "ok":
                    self.logger.error(f"Database integrity check failed: {integrity_result}")
                    return False
                
                # Verify required tables exist
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name IN ('scans', 'scan_results', 'classifications')
                """)
                tables = [row[0] for row in cursor.fetchall()]
                required_tables = {'scans', 'scan_results', 'classifications'}
                
                if not required_tables.issubset(set(tables)):
                    missing_tables = required_tables - set(tables)
                    self.logger.error(f"Missing required tables: {missing_tables}")
                    return False
                
                # Verify table schemas
                for table in required_tables:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = cursor.fetchall()
                    if not columns:
                        self.logger.error(f"Table {table} has no columns")
                        return False
                
                return True
                
        except sqlite3.Error as e:
            self.logger.error(f"Database validation failed: {e}")
            return False

    def create_database(self) -> None:
        """Create database schema if it doesn't exist."""
        try:
            # Ensure parent directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Enable foreign key constraints
                cursor.execute("PRAGMA foreign_keys = ON")
                
                # Create scans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        ip_version INTEGER NOT NULL CHECK (ip_version IN (4, 6)),
                        scan_timestamp DATETIME NOT NULL,
                        scan_duration_ms INTEGER CHECK (scan_duration_ms >= 0),
                        modules_executed TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create scan_results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        module_name TEXT NOT NULL,
                        result_data TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        error_message TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create classifications table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS classifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        ip_range TEXT NOT NULL,
                        description TEXT,
                        qualifies_for TEXT NOT NULL,
                        rfc_reference TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_ip_address ON scans(ip_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_classifications_name ON classifications(name)")
                
                conn.commit()
                
                # Set schema version
                current_version = self._get_schema_version()
                if current_version == 0:
                    self._set_schema_version(self.SCHEMA_VERSION)
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create database: {e}")

    def migrate_database(self) -> None:
        """Perform database schema migrations if needed."""
        current_version = self._get_schema_version()
        
        if current_version < self.SCHEMA_VERSION:
            self.logger.info(f"Migrating database from version {current_version} to {self.SCHEMA_VERSION}")
            
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Future migrations would go here
                    # For now, we only have version 1
                    if current_version == 0:
                        # This is handled in create_database()
                        pass
                    
                    self._set_schema_version(self.SCHEMA_VERSION)
                    conn.commit()
                    
            except sqlite3.Error as e:
                raise DatabaseError(f"Database migration failed: {e}")

    def check_database_health(self) -> Dict[str, Union[bool, str, int]]:
        """
        Perform comprehensive database health check.
        
        Returns:
            Dictionary with health check results
        """
        health_status = {
            'exists': False,
            'readable': False,
            'writable': False,
            'integrity_ok': False,
            'schema_version': 0,
            'total_scans': 0,
            'errors': []
        }
        
        try:
            # Check if database file exists
            health_status['exists'] = self.db_path.exists()
            
            if not health_status['exists']:
                health_status['errors'].append("Database file does not exist")
                return health_status
            
            # Check readability
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1")
                    health_status['readable'] = True
            except sqlite3.Error as e:
                health_status['errors'].append(f"Database not readable: {e}")
            
            # Check writability (try to create a temporary table)
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("CREATE TEMPORARY TABLE test_write (id INTEGER)")
                    cursor.execute("DROP TABLE test_write")
                    health_status['writable'] = True
            except sqlite3.Error as e:
                health_status['errors'].append(f"Database not writable: {e}")
            
            # Check integrity
            health_status['integrity_ok'] = self._validate_database_integrity()
            
            # Get schema version
            health_status['schema_version'] = self._get_schema_version()
            
            # Count total scans
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM scans")
                    health_status['total_scans'] = cursor.fetchone()[0]
            except sqlite3.Error as e:
                health_status['errors'].append(f"Could not count scans: {e}")
            
        except Exception as e:
            health_status['errors'].append(f"Health check failed: {e}")
        
        return health_status

    def store_scan_result(self, result: Dict) -> int:
        """
        Store analysis result in database.

        Args:
            result: Analysis result dictionary to store

        Returns:
            ID of the stored scan record
            
        Raises:
            DatabaseError: If storage operation fails
        """
        try:
            self.create_database()  # Ensure database exists
            
            # Validate input data
            if not result.get('ip_address'):
                raise DatabaseError("IP address is required")
            
            ip_version = result.get('ip_version', 4)
            if ip_version not in (4, 6):
                raise DatabaseError(f"Invalid IP version: {ip_version}")
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Enable foreign key constraints
                cursor.execute("PRAGMA foreign_keys = ON")
                
                # Extract basic scan information
                ip_address = str(result.get('ip_address', ''))
                scan_timestamp = result.get('scan_timestamp', datetime.now())
                scan_duration_ms = result.get('scan_duration_ms', 0)
                modules_executed = json.dumps(result.get('modules_executed', []))
                
                # Validate scan duration
                if scan_duration_ms < 0:
                    raise DatabaseError("Scan duration cannot be negative")
                
                # Convert datetime to ISO string to avoid deprecation warning
                if isinstance(scan_timestamp, datetime):
                    timestamp_str = scan_timestamp.isoformat()
                else:
                    timestamp_str = str(scan_timestamp)
                
                # Insert scan record
                cursor.execute("""
                    INSERT INTO scans (ip_address, ip_version, scan_timestamp, scan_duration_ms, modules_executed)
                    VALUES (?, ?, ?, ?, ?)
                """, (ip_address, ip_version, timestamp_str, scan_duration_ms, modules_executed))
                
                scan_id = cursor.lastrowid
                
                if not scan_id:
                    raise DatabaseError("Failed to get scan ID after insertion")
                
                # Store module results
                for module_name, module_result in result.get('module_results', {}).items():
                    if not isinstance(module_result, dict):
                        self.logger.warning(f"Invalid module result format for {module_name}")
                        continue
                        
                    success = module_result.get('success', True)
                    result_data = json.dumps(module_result.get('data', {}))
                    error_message = module_result.get('error_message')
                    
                    cursor.execute("""
                        INSERT INTO scan_results (scan_id, module_name, result_data, success, error_message)
                        VALUES (?, ?, ?, ?, ?)
                    """, (scan_id, module_name, result_data, success, error_message))
                
                conn.commit()
                return scan_id
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to store scan result: {e}")
        except (json.JSONDecodeError, TypeError) as e:
            raise DatabaseError(f"Failed to serialize scan data: {e}")

    def get_scan_history(self, ip_address: str) -> List[Dict]:
        """
        Retrieve scan history for an IP address.

        Args:
            ip_address: IP address to query history for

        Returns:
            List of historical scan records
            
        Raises:
            DatabaseError: If retrieval operation fails
        """
        if not ip_address:
            raise DatabaseError("IP address is required")
            
        if not self.db_path.exists():
            return []
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT s.id, s.ip_address, s.ip_version, s.scan_timestamp, 
                           s.scan_duration_ms, s.modules_executed,
                           sr.module_name, sr.result_data, sr.success, sr.error_message
                    FROM scans s
                    LEFT JOIN scan_results sr ON s.id = sr.scan_id
                    WHERE s.ip_address = ?
                    ORDER BY s.scan_timestamp DESC
                """, (ip_address,))
                
                rows = cursor.fetchall()
                
                # Group results by scan
                scans = {}
                for row in rows:
                    scan_id = row[0]
                    if scan_id not in scans:
                        scans[scan_id] = {
                            'id': row[0],
                            'ip_address': row[1],
                            'ip_version': row[2],
                            'scan_timestamp': row[3],
                            'scan_duration_ms': row[4],
                            'modules_executed': json.loads(row[5]) if row[5] else [],
                            'module_results': {}
                        }
                    
                    # Add module result if present
                    if row[6]:  # module_name
                        try:
                            result_data = json.loads(row[7]) if row[7] else {}
                        except json.JSONDecodeError:
                            self.logger.warning(f"Invalid JSON in result data for scan {scan_id}, module {row[6]}")
                            result_data = {}
                            
                        scans[scan_id]['module_results'][row[6]] = {
                            'data': result_data,
                            'success': bool(row[8]),
                            'error_message': row[9]
                        }
                
                return list(scans.values())
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve scan history: {e}")

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict]:
        """
        Retrieve a specific scan by ID.

        Args:
            scan_id: ID of the scan to retrieve

        Returns:
            Scan record dictionary or None if not found
            
        Raises:
            DatabaseError: If retrieval operation fails
        """
        if not isinstance(scan_id, int) or scan_id <= 0:
            raise DatabaseError("Valid scan ID is required")
            
        if not self.db_path.exists():
            return None
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT s.id, s.ip_address, s.ip_version, s.scan_timestamp, 
                           s.scan_duration_ms, s.modules_executed,
                           sr.module_name, sr.result_data, sr.success, sr.error_message
                    FROM scans s
                    LEFT JOIN scan_results sr ON s.id = sr.scan_id
                    WHERE s.id = ?
                """, (scan_id,))
                
                rows = cursor.fetchall()
                
                if not rows:
                    return None
                
                # Build scan record
                first_row = rows[0]
                scan = {
                    'id': first_row[0],
                    'ip_address': first_row[1],
                    'ip_version': first_row[2],
                    'scan_timestamp': first_row[3],
                    'scan_duration_ms': first_row[4],
                    'modules_executed': json.loads(first_row[5]) if first_row[5] else [],
                    'module_results': {}
                }
                
                # Add module results
                for row in rows:
                    if row[6]:  # module_name
                        try:
                            result_data = json.loads(row[7]) if row[7] else {}
                        except json.JSONDecodeError:
                            self.logger.warning(f"Invalid JSON in result data for scan {scan_id}, module {row[6]}")
                            result_data = {}
                            
                        scan['module_results'][row[6]] = {
                            'data': result_data,
                            'success': bool(row[8]),
                            'error_message': row[9]
                        }
                
                return scan
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve scan by ID: {e}")

    def cleanup_old_scans(self, days_to_keep: int = 30) -> int:
        """
        Remove scan records older than specified number of days.
        
        Args:
            days_to_keep: Number of days of scan history to retain
            
        Returns:
            Number of scans deleted
            
        Raises:
            DatabaseError: If cleanup operation fails
        """
        if days_to_keep <= 0:
            raise DatabaseError("Days to keep must be positive")
            
        if not self.db_path.exists():
            return 0
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Enable foreign key constraints for cascade delete
                cursor.execute("PRAGMA foreign_keys = ON")
                
                # Calculate cutoff date
                cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                cutoff_date = cutoff_date.replace(day=cutoff_date.day - days_to_keep)
                
                # Count scans to be deleted
                cursor.execute("""
                    SELECT COUNT(*) FROM scans 
                    WHERE scan_timestamp < ?
                """, (cutoff_date.isoformat(),))
                
                count_to_delete = cursor.fetchone()[0]
                
                if count_to_delete > 0:
                    # Delete old scans (scan_results will be deleted by cascade)
                    cursor.execute("""
                        DELETE FROM scans 
                        WHERE scan_timestamp < ?
                    """, (cutoff_date.isoformat(),))
                    
                    conn.commit()
                    self.logger.info(f"Cleaned up {count_to_delete} old scan records")
                
                return count_to_delete
                
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to cleanup old scans: {e}")
