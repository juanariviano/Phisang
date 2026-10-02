-- Additive and safe to run again. Adds the review trail to false-positive
-- reports, and the per-address approval an admin can grant or lift.
IF COL_LENGTH('dbo.FalsePositiveReports', 'ReviewedAt') IS NULL
    ALTER TABLE dbo.FalsePositiveReports ADD ReviewedAt DATETIME2(3) NULL;
IF COL_LENGTH('dbo.FalsePositiveReports', 'ReviewedBy') IS NULL
    ALTER TABLE dbo.FalsePositiveReports ADD ReviewedBy NVARCHAR(255) NULL;
IF COL_LENGTH('dbo.FalsePositiveReports', 'ReviewNote') IS NULL
    ALTER TABLE dbo.FalsePositiveReports ADD ReviewNote NVARCHAR(1000) NULL;

-- On the site rather than the report: approval describes the address, so a later
-- report about the same URL inherits it and lifting it is a single update.
IF COL_LENGTH('dbo.Sites', 'ApprovedAt') IS NULL
    ALTER TABLE dbo.Sites ADD ApprovedAt DATETIME2(3) NULL;
IF COL_LENGTH('dbo.Sites', 'ApprovedBy') IS NULL
    ALTER TABLE dbo.Sites ADD ApprovedBy NVARCHAR(255) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes
               WHERE name = 'IX_FalsePositiveReports_ReviewStatus'
                 AND object_id = OBJECT_ID('dbo.FalsePositiveReports'))
    CREATE INDEX IX_FalsePositiveReports_ReviewStatus
        ON dbo.FalsePositiveReports (ReviewStatus, CreatedAt DESC);
