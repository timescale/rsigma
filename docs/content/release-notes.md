---
description: "RSigma release notes and changelog: every released version of the Sigma detection engineering toolkit, with new features, fixes, and breaking changes."
---

{%
   include-markdown "../../CHANGELOG.md"
%}

## Version tags {#version-tags}

This site is published from the `main` branch, so it can describe changes that are not in a release yet. Tags show when something became available, and each tag links to its release notes:

- A tag below a page title gives the release that added the command or feature, for example {{ added "0.22.0" }} on a page added in v0.22.0. Every CLI command page has one; commands that predate v0.12.0 show v0.12.0, the release that moved the CLI to command groups and gave them their current names. Guide and reference pages without a tag describe features available since v0.12.0.
- A tag on a section, flag, config key, or table row marks an addition made to an existing page from v0.22.0 onward. For older changes within a page, see the list above.
- {{ added "unreleased" }} marks a change merged to `main` that is not in a release yet. <!-- keep-unreleased: this tag illustrates the badge, so release promotion skips this line. -->

Run `rsigma --version` to see which release you have.
