# --- migrate_to_supabase.py ---
"""
Migration script to move from SQLite to Supabase PostgreSQL
Run this script to migrate all your data to Supabase
"""

import os
import sys
import json
import logging
from datetime import datetime
from sqlalchemy import create_engine, text, MetaData, Table
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)

class SupabaseMigration:
    """Handle migration from SQLite to Supabase PostgreSQL"""
    
    def __init__(self):
        # Source (SQLite)
        self.sqlite_path = "amco.bybinary_dashboard.db"
        self.sqlite_url = f"sqlite:///{self.sqlite_path}"
        
        # Target (Supabase PostgreSQL)
        self.postgres_url = os.getenv('DATABASE_URL')
        
        if not self.postgres_url:
            raise ValueError("DATABASE_URL environment variable not set. Please configure Supabase connection.")
        
        # Create engines
        self.sqlite_engine = create_engine(self.sqlite_url)
        self.postgres_engine = create_engine(self.postgres_url)
        
        # Create sessions
        self.sqlite_session = sessionmaker(bind=self.sqlite_engine)()
        self.postgres_session = sessionmaker(bind=self.postgres_engine)()
    
    def test_connections(self):
        """Test both database connections"""
        try:
            # Test SQLite
            with self.sqlite_engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                log.info("✅ SQLite connection successful")
            
            # Test PostgreSQL
            with self.postgres_engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                conn.commit()
                log.info("✅ Supabase PostgreSQL connection successful")
            
            return True
        except Exception as e:
            log.error(f"❌ Connection test failed: {e}")
            return False
    
    def create_tables_in_postgres(self):
        """Create tables in PostgreSQL using SQLAlchemy models"""
        try:
            # Import models to ensure they're registered
            from database.models import Base
            
            # Create all tables
            Base.metadata.create_all(self.postgres_engine)
            log.info("✅ Tables created in Supabase PostgreSQL")
            return True
        except Exception as e:
            log.error(f"❌ Error creating tables: {e}")
            return False
    
    def migrate_table_data(self, table_name: str):
        """Migrate data from one table"""
        try:
            log.info(f"📦 Migrating table: {table_name}")
            
            # Get data from SQLite
            sqlite_data = self.sqlite_session.execute(
                text(f"SELECT * FROM {table_name}")
            ).fetchall()
            
            if not sqlite_data:
                log.info(f"   No data found in {table_name}")
                return True
            
            # Get column names
            columns = sqlite_data[0]._fields if hasattr(sqlite_data[0], '_fields') else sqlite_data[0].keys()
            
            # Insert data into PostgreSQL
            for row in sqlite_data:
                row_dict = dict(zip(columns, row)) if hasattr(row, '_fields') else dict(row._mapping)
                
                # Handle special data type conversions
                row_dict = self._convert_data_types(row_dict, table_name)
                
                # Create insert statement
                columns_str = ', '.join(row_dict.keys())
                values_str = ', '.join([f":{key}" for key in row_dict.keys()])
                
                insert_sql = f"INSERT INTO {table_name} ({columns_str}) VALUES ({values_str})"
                
                self.postgres_session.execute(text(insert_sql), row_dict)
            
            self.postgres_session.commit()
            log.info(f"✅ Migrated {len(sqlite_data)} records from {table_name}")
            return True
            
        except Exception as e:
            log.error(f"❌ Error migrating {table_name}: {e}")
            self.postgres_session.rollback()
            return False
    
    def _convert_data_types(self, row_dict: dict, table_name: str) -> dict:
        """Convert data types for PostgreSQL compatibility"""
        
        # Handle datetime fields
        datetime_fields = {
            'users': ['created_at', 'last_access'],
            'agents': ['created_at', 'updated_at'],
            'queries': ['created_at'],
            'conversations': ['created_at', 'updated_at'],
            'configurations': ['created_at', 'updated_at'],
            'role_agent_access': ['created_at', 'updated_at'],
            'user_preferences': ['created_at', 'updated_at']
        }
        
        if table_name in datetime_fields:
            for field in datetime_fields[table_name]:
                if field in row_dict and row_dict[field]:
                    # Convert string datetime to proper datetime object if needed
                    if isinstance(row_dict[field], str):
                        try:
                            row_dict[field] = datetime.fromisoformat(row_dict[field].replace('Z', '+00:00'))
                        except:
                            pass
        
        # Handle JSON fields
        json_fields = {
            'agents': ['skills', 'goals', 'personality']
        }
        
        if table_name in json_fields:
            for field in json_fields[table_name]:
                if field in row_dict and row_dict[field]:
                    if isinstance(row_dict[field], str):
                        try:
                            # Validate JSON
                            json.loads(row_dict[field])
                        except:
                            # If not valid JSON, make it a JSON array
                            row_dict[field] = json.dumps([row_dict[field]])
        
        return row_dict
    
    def migrate_all_data(self):
        """Migrate all data from SQLite to PostgreSQL"""
        
        # Define migration order (respecting foreign key constraints)
        migration_order = [
            'configurations',
            'roles', 
            'users',
            'agent_options_language_models',
            'agent_options_skills', 
            'agent_options_personalities',
            'agent_options_goals',
            'agents',
            'role_agent_access',
            'user_preferences',
            'conversations',
            'queries'
        ]
        
        success_count = 0
        
        for table_name in migration_order:
            try:
                # Check if table exists in SQLite
                result = self.sqlite_session.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"),
                    {"table_name": table_name}
                ).fetchone()
                
                if result:
                    if self.migrate_table_data(table_name):
                        success_count += 1
                else:
                    log.info(f"⏭️  Table {table_name} not found in SQLite, skipping")
                    
            except Exception as e:
                log.error(f"❌ Failed to migrate {table_name}: {e}")
        
        log.info(f"✅ Migration completed! {success_count}/{len(migration_order)} tables migrated successfully")
        return success_count == len([t for t in migration_order if self._table_exists_in_sqlite(t)])
    
    def _table_exists_in_sqlite(self, table_name: str) -> bool:
        """Check if table exists in SQLite"""
        try:
            result = self.sqlite_session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"),
                {"table_name": table_name}
            ).fetchone()
            return result is not None
        except:
            return False
    
    def create_backup(self):
        """Create backup of current data"""
        try:
            backup_dir = "backups"
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{backup_dir}/sqlite_backup_{timestamp}.sql"
            
            # Simple backup - copy the SQLite file
            import shutil
            shutil.copy2(self.sqlite_path, f"{backup_dir}/sqlite_backup_{timestamp}.db")
            
            log.info(f"✅ Backup created: {backup_dir}/sqlite_backup_{timestamp}.db")
            return True
        except Exception as e:
            log.error(f"❌ Backup failed: {e}")
            return False
    
    def verify_migration(self):
        """Verify that migration was successful"""
        try:
            log.info("🔍 Verifying migration...")
            
            # Get table counts from both databases
            tables_to_check = ['users', 'agents', 'conversations', 'queries']
            
            for table in tables_to_check:
                if not self._table_exists_in_sqlite(table):
                    continue
                
                # SQLite count
                sqlite_count = self.sqlite_session.execute(
                    text(f"SELECT COUNT(*) FROM {table}")
                ).scalar()
                
                # PostgreSQL count
                postgres_count = self.postgres_session.execute(
                    text(f"SELECT COUNT(*) FROM {table}")
                ).scalar()
                
                if sqlite_count == postgres_count:
                    log.info(f"✅ {table}: {sqlite_count} records (match)")
                else:
                    log.warning(f"⚠️  {table}: SQLite={sqlite_count}, PostgreSQL={postgres_count} (mismatch)")
            
            log.info("✅ Migration verification completed")
            return True
            
        except Exception as e:
            log.error(f"❌ Verification failed: {e}")
            return False

def main():
    """Main migration function"""
    print("🚀 Starting Supabase Migration")
    print("=" * 50)
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        print("❌ .env file not found!")
        print("Please create a .env file with your Supabase configuration:")
        print("DATABASE_URL=postgresql://postgres:password@project.supabase.co:5432/postgres")
        return
    
    try:
        migration = SupabaseMigration()
        
        # Step 1: Test connections
        if not migration.test_connections():
            return
        
        # Step 2: Create backup
        print("\n📦 Creating backup...")
        if not migration.create_backup():
            print("⚠️  Backup failed, but continuing...")
        
        # Step 3: Create tables in PostgreSQL
        print("\n🏗️  Creating tables in Supabase...")
        if not migration.create_tables_in_postgres():
            return
        
        # Step 4: Migrate data
        print("\n📊 Migrating data...")
        if migration.migrate_all_data():
            print("\n✅ Data migration completed successfully!")
        else:
            print("\n❌ Data migration completed with errors")
            return
        
        # Step 5: Verify migration
        print("\n🔍 Verifying migration...")
        migration.verify_migration()
        
        print("\n" + "=" * 50)
        print("🎉 Migration to Supabase completed!")
        print("\nNext steps:")
        print("1. Update your .env file to use DATABASE_URL")
        print("2. Test your application with the new database")
        print("3. Update your deployment configuration")
        
    except Exception as e:
        log.error(f"❌ Migration failed: {e}")
        print(f"\n❌ Migration failed: {e}")

if __name__ == "__main__":
    main()
