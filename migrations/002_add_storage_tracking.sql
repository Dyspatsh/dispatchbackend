-- Function to update storage used when files are uploaded
CREATE OR REPLACE FUNCTION update_storage_used()
RETURNS TRIGGER AS $$
BEGIN
    -- Add file size to sender's storage used
    UPDATE users 
    SET storage_used_mb = storage_used_mb + (NEW.file_size / 1024 / 1024)
    WHERE id = NEW.sender_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to decrease storage when files are deleted
CREATE OR REPLACE FUNCTION decrease_storage_used()
RETURNS TRIGGER AS $$
BEGIN
    -- Subtract file size from sender's storage used
    UPDATE users 
    SET storage_used_mb = GREATEST(0, storage_used_mb - (OLD.file_size / 1024 / 1024))
    WHERE id = OLD.sender_id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Create triggers
DROP TRIGGER IF EXISTS track_file_upload ON files;
CREATE TRIGGER track_file_upload
    AFTER INSERT ON files
    FOR EACH ROW
    EXECUTE FUNCTION update_storage_used();

DROP TRIGGER IF EXISTS track_file_delete ON files;
CREATE TRIGGER track_file_delete
    BEFORE DELETE ON files
    FOR EACH ROW
    EXECUTE FUNCTION decrease_storage_used();

-- Add check constraint to prevent exceeding quota (optional)
-- This requires modifying the Rust code to check before insert
