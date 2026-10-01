-- Additive and safe to run again. Holds the reports users file against a verdict
-- they believe is wrong; nothing here feeds back into scanning.
IF OBJECT_ID('dbo.FalsePositiveReports', 'U') IS NULL
    CREATE TABLE dbo.FalsePositiveReports (
        ReportId               BIGINT IDENTITY(1,1) NOT NULL
            CONSTRAINT PK_FalsePositiveReports PRIMARY KEY,
        ScanRef                NVARCHAR(32)   NOT NULL,
        SiteId                 BIGINT         NULL
            CONSTRAINT FK_FalsePositiveReports_Sites FOREIGN KEY REFERENCES dbo.Sites (SiteId),
        UrlHash                CHAR(64)       NOT NULL,
        NormalizedUrl          NVARCHAR(2048) NOT NULL,
        Client                 NVARCHAR(20)   NULL,
        -- The verdict as it stood when the report was filed, so a later rescan
        -- cannot rewrite what the reporter was actually disagreeing with.
        ReportedVerdict        VARCHAR(20)    NULL,
        ReportedClassification VARCHAR(20)    NULL,
        ReportedRiskScore      FLOAT          NULL,
        Reason                 NVARCHAR(1000) NULL,
        ReviewStatus           VARCHAR(20)    NOT NULL
            CONSTRAINT DF_FalsePositiveReports_ReviewStatus DEFAULT ('new'),
        CreatedAt              DATETIME2(3)   NOT NULL
            CONSTRAINT DF_FalsePositiveReports_CreatedAt DEFAULT (sysutcdatetime())
    );

-- Guarded separately so a database that already has the table still gets these.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
               WHERE name = 'IX_FalsePositiveReports_UrlHash'
                 AND object_id = OBJECT_ID('dbo.FalsePositiveReports'))
    CREATE INDEX IX_FalsePositiveReports_UrlHash ON dbo.FalsePositiveReports (UrlHash);

IF NOT EXISTS (SELECT 1 FROM sys.indexes
               WHERE name = 'IX_FalsePositiveReports_CreatedAt'
                 AND object_id = OBJECT_ID('dbo.FalsePositiveReports'))
    CREATE INDEX IX_FalsePositiveReports_CreatedAt ON dbo.FalsePositiveReports (CreatedAt DESC);
