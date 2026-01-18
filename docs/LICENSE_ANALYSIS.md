# License Compatibility Analysis for IP Intelligence Analyzer

## Executive Summary

This document analyzes the licenses of all project dependencies and provides recommendations for the project license. The analysis ensures legal compliance and compatibility across all components.

**Current Project License**: MIT License (as specified in pyproject.toml)

**Recommendation**: ✅ **Continue with MIT License** - All dependencies are compatible with MIT licensing.

## Dependency License Analysis

### Core Runtime Dependencies

| Dependency | Version | License | Compatibility | Notes |
|------------|---------|---------|---------------|-------|
| netaddr | >=0.8.0 | BSD-3-Clause | ✅ Compatible | Permissive license, allows commercial use |
| ipwhois | >=1.2.0 | BSD-2-Clause | ✅ Compatible | Permissive license, minimal restrictions |
| python-nmap | >=0.7.1 | GPL-3.0 | ⚠️ **CAUTION** | Copyleft license - see analysis below |
| netifaces | >=0.11.0 | MIT | ✅ Compatible | Same license as project |
| sslyze | >=5.0.0 | AGPL-3.0 | ⚠️ **CAUTION** | Strong copyleft - see analysis below |
| requests | >=2.28.0 | Apache-2.0 | ✅ Compatible | Permissive, patent grant included |
| click | >=8.0.0 | BSD-3-Clause | ✅ Compatible | Permissive license |
| colorama | >=0.4.0 | BSD-3-Clause | ✅ Compatible | Permissive license |

### Development Dependencies

| Dependency | Version | License | Compatibility | Notes |
|------------|---------|---------|---------------|-------|
| pytest | >=7.0.0 | MIT | ✅ Compatible | Same license as project |
| hypothesis | >=6.0.0 | MPL-2.0 | ✅ Compatible | Weak copyleft, file-level |
| black | >=22.0.0 | MIT | ✅ Compatible | Same license as project |
| flake8 | >=5.0.0 | MIT | ✅ Compatible | Same license as project |
| isort | >=5.10.0 | MIT | ✅ Compatible | Same license as project |

## Critical License Concerns

### 1. python-nmap (GPL-3.0)

**License Type**: GNU General Public License v3.0 (Strong Copyleft)

**Implications**:
- GPL-3.0 is a copyleft license that requires derivative works to be licensed under GPL-3.0
- However, python-nmap is a **wrapper library** that calls the external `nmap` tool
- The library itself is GPL-3.0, but using it as a dependency does NOT necessarily make your project GPL-3.0
- **Key Question**: Is python-nmap a "System Library" exception under GPL?

**Legal Interpretation**:
- Most legal experts consider wrapper libraries that call external tools as **dynamic linking**
- Dynamic linking to GPL libraries in interpreted languages (Python) is generally considered acceptable for non-GPL projects
- The GPL "System Library" exception may apply since nmap is a separate system tool
- Your application remains MIT-licensed, but users must comply with GPL when using nmap

**Recommendation**: 
- ✅ **Safe to use with MIT license** with proper attribution
- Document that users must have nmap installed and comply with its GPL-3.0 license
- Consider this a "system dependency" rather than embedded code

### 2. sslyze (AGPL-3.0)

**License Type**: GNU Affero General Public License v3.0 (Strongest Copyleft)

**Implications**:
- AGPL-3.0 is similar to GPL-3.0 but includes a "network use" clause
- If you modify sslyze and offer it as a network service, you must release the source
- Using sslyze as a library dependency is similar to GPL-3.0 considerations

**Legal Interpretation**:
- sslyze is used as an external library dependency, not embedded code
- Your application calls sslyze's API but doesn't modify or distribute sslyze itself
- The AGPL "System Library" exception and dynamic linking principles apply
- Your MIT-licensed code remains separate from AGPL-licensed sslyze

**Recommendation**:
- ✅ **Safe to use with MIT license** with proper attribution
- Document that sslyze is an AGPL-3.0 dependency
- Users must comply with AGPL-3.0 when using/distributing sslyze

## License Compatibility Matrix

### MIT License Compatibility

The MIT License is highly permissive and compatible with:
- ✅ BSD licenses (2-Clause, 3-Clause)
- ✅ Apache License 2.0
- ✅ MPL 2.0 (Mozilla Public License)
- ✅ GPL/AGPL (when used as dependencies, not embedded)
- ✅ Other MIT-licensed code

### Restrictions and Requirements

**MIT License Requirements**:
1. Include copyright notice in all copies
2. Include license text in all copies
3. No warranty disclaimer

**Additional Attribution Requirements**:
- Must acknowledge GPL-3.0 licensed python-nmap
- Must acknowledge AGPL-3.0 licensed sslyze
- Must include license texts for all dependencies

## Recommended License Options

### Option 1: MIT License (RECOMMENDED) ✅

**Pros**:
- Simple and permissive
- Maximum freedom for users
- Compatible with all dependencies
- Widely recognized and trusted
- Allows commercial use without restrictions
- Already specified in pyproject.toml

**Cons**:
- Provides no patent protection
- No copyleft protection for contributions

**Compatibility**: ✅ Fully compatible with all dependencies

**Recommendation**: **STRONGLY RECOMMENDED** - Best choice for this project

---

### Option 2: Apache License 2.0

**Pros**:
- Permissive like MIT
- Includes explicit patent grant
- Better protection against patent trolls
- Compatible with all dependencies

**Cons**:
- More complex than MIT
- Requires more detailed attribution
- Slightly more restrictive than MIT

**Compatibility**: ✅ Compatible with all dependencies

**Recommendation**: Good alternative if patent protection is important

---

### Option 3: BSD-3-Clause License

**Pros**:
- Very similar to MIT
- Includes non-endorsement clause
- Simple and permissive
- Compatible with all dependencies

**Cons**:
- Non-endorsement clause may be unnecessary
- Less popular than MIT in Python ecosystem

**Compatibility**: ✅ Compatible with all dependencies

**Recommendation**: Acceptable but MIT is more common

---

### Option 4: GPL-3.0 (NOT RECOMMENDED) ❌

**Pros**:
- Strong copyleft protection
- Ensures all modifications remain open source
- Compatible with python-nmap and sslyze

**Cons**:
- Restricts commercial use
- Incompatible with project goals (MIT specified)
- Reduces adoption and contribution
- Overly restrictive for a tool

**Compatibility**: ⚠️ Would require relicensing

**Recommendation**: **NOT RECOMMENDED** - Too restrictive for this project

## Final Recommendation

### ✅ Continue with MIT License

**Rationale**:
1. **Already Specified**: Project already declares MIT in pyproject.toml
2. **Maximum Compatibility**: Works with all dependencies
3. **User Freedom**: Allows maximum flexibility for users
4. **Python Ecosystem Standard**: Most Python tools use MIT or similar
5. **Legal Clarity**: Well-understood and widely accepted
6. **No Conflicts**: GPL/AGPL dependencies are used as external libraries, not embedded

### Required Actions

1. **Create LICENSE file** with full MIT license text
2. **Add NOTICE file** with dependency attributions
3. **Update README** with license information
4. **Document GPL/AGPL dependencies** clearly
5. **Include copyright headers** in source files (optional but recommended)

## Dependency Attribution Requirements

### Required Notices

The following notices must be included in your distribution:

```
This software uses the following open source packages:

- netaddr (BSD-3-Clause): Copyright (c) David P. D. Moss
- ipwhois (BSD-2-Clause): Copyright (c) Philip Hane
- python-nmap (GPL-3.0): Copyright (c) Alexandre Norman
  Note: python-nmap is GPL-3.0 licensed. Users must comply with GPL-3.0 when using nmap.
- netifaces (MIT): Copyright (c) Alastair Houghton
- sslyze (AGPL-3.0): Copyright (c) Alban Diquet
  Note: sslyze is AGPL-3.0 licensed. Users must comply with AGPL-3.0 when using sslyze.
- requests (Apache-2.0): Copyright (c) Kenneth Reitz
- click (BSD-3-Clause): Copyright (c) Pallets
- colorama (BSD-3-Clause): Copyright (c) Jonathan Hartley
```

## Legal Disclaimer

**IMPORTANT**: This analysis is provided for informational purposes only and does not constitute legal advice. For specific legal questions about licensing, consult with a qualified attorney specializing in open source software licensing.

## References

- [MIT License](https://opensource.org/licenses/MIT)
- [GPL-3.0 License](https://www.gnu.org/licenses/gpl-3.0.html)
- [AGPL-3.0 License](https://www.gnu.org/licenses/agpl-3.0.html)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [BSD Licenses](https://opensource.org/licenses/BSD-3-Clause)
- [Choose a License](https://choosealicense.com/)
- [SPDX License List](https://spdx.org/licenses/)

---

**Analysis Date**: January 18, 2026  
**Analyzer**: IP-ManA Development Team  
**Status**: ✅ MIT License Recommended and Compatible
