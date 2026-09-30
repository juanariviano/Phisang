-- Additive and safe to run again. Existing scan records remain readable.
IF COL_LENGTH('dbo.Scans', 'ScreenshotJpeg') IS NULL
    ALTER TABLE dbo.Scans ADD ScreenshotJpeg VARBINARY(MAX) NULL;
IF COL_LENGTH('dbo.Scans', 'ExplanationJson') IS NULL
    ALTER TABLE dbo.Scans ADD ExplanationJson NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.Scans', 'ExplanationKey') IS NULL
    ALTER TABLE dbo.Scans ADD ExplanationKey VARCHAR(64) NULL;
