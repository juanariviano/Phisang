# PhiUSIIL URL-only EDA and cleaning report

Pipeline version: 1.0.0

## Dataset flow

| Measure | Value |
|---|---:|
| Source rows | 235,795 |
| Source columns | 56 |
| Exact duplicate rows | 425 |
| Invalid rows removed | 4 |
| Normalized duplicate rows removed | 900 |
| Normalized URL keys with conflicting labels | 1 |
| Rows removed for normalized-label conflicts | 2 |
| Clean rows | 234,890 |
| Clean columns | 35 |

## Labels

The source uses 0 for phishing and 1 for legitimate. The cleaned dataset intentionally uses is_phishing=1 for phishing and is_phishing=0 for legitimate.

| Dataset | Legitimate | Phishing |
|---|---:|---:|
| Source | 134,850 | 100,945 |
| Clean | 134,849 | 100,041 |

## Source collection-bias checks

| Pattern | Phishing | Legitimate |
|---|---:|---:|
| has_non_root_path | 27.199% | 0.000% |
| has_query | 6.022% | 0.000% |
| has_www_prefix | 41.353% | 100.000% |
| url_similarity_index_is_100 | 0.779% | 100.000% |
| uses_https | 48.735% | 100.000% |

These differences are dataset-source shortcuts, not proof of phishing. A random row split will substantially overstate generalization.

## Cleaning and preprocessing

- Accepted HTTP and HTTPS URLs up to 4,096 characters.
- Lowercased and IDNA-normalized hostnames and removed default ports.
- Removed URL user credentials while retaining a has_userinfo risk feature.
- Removed destination-page features because Phisang never fetches submitted pages.
- Removed direct label proxies and corpus-derived probability fields.
- Recomputed every output feature from the URL using this pipeline.
- Deduplicated by normalized URL and dropped any normalized URL with conflicting labels.

### Removed feature groups

- Page-derived columns (29): LineOfCode, LargestLineLength, HasTitle, Title, DomainTitleMatchScore, URLTitleMatchScore, HasFavicon, Robots, IsResponsive, NoOfURLRedirect, NoOfSelfRedirect, HasDescription, NoOfPopup, NoOfiFrame, HasExternalFormSubmit, HasSocialNet, HasSubmitButton, HasHiddenFields, HasPasswordField, Bank, Pay, Crypto, HasCopyrightInfo, NoOfImage, NoOfCSS, NoOfJS, NoOfSelfRef, NoOfEmptyRef, NoOfExternalRef
- Leakage-prone columns (6): FILENAME, URLSimilarityIndex, TLDLegitimateProb, URLCharProb, CharContinuationRate, IsHTTPS

## Strongest cleaned-feature correlations

Correlation is descriptive only; large values may still reflect collection bias.

| Feature | Pearson correlation with is_phishing |
|---|---:|
| digit_ratio | 0.434636 |
| url_entropy | 0.404028 |
| path_depth | 0.334755 |
| host_hyphen_count | 0.304674 |
| hostname_length | 0.281841 |
| hostname_entropy | 0.275574 |
| special_ratio | -0.270717 |
| slash_count | 0.262590 |
| url_length | 0.255757 |
| letter_count | 0.249277 |
| letter_ratio | -0.241218 |
| hyphen_count | 0.233365 |

## Training guidance

- Split by public-suffix-aware registered domain, never by random row.
- Validate against a second, independently sourced and more recent dataset.
- Add legitimate deep links, query strings, and non-www hosts before claiming real-world performance.
- Treat the target as phishing risk only. URLhaus remains the known-malware signal.
- Do not present an uncalibrated model probability as confidence.

## Reproducibility

- Input SHA-256: a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6
- Output SHA-256: 9092009ad7446bf65c9f7618e4a8dd6943b2acc4d1c4efd110f286c23febdbad
