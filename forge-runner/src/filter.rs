use clap::Parser;
use foundry_common::TestFilter;
use foundry_compilers::{FileFilter, ProjectPathsConfig};
use foundry_config::{filter::GlobMatcher, Config};
use std::{fmt, path::Path};

/// The filter to use during testing.
///
/// See also `FileFilter`.
#[derive(Clone, Parser)]
#[command(next_help_heading = "Test filtering")]
pub struct CustomFilterArgs {
    /// Only run test functions matching the specified regex pattern.
    #[arg(long = "filter-match-test", visible_alias = "fmt", value_name = "REGEX")]
    pub filter_test_pattern: Option<regex::Regex>,

    /// Only run test functions that do not match the specified regex pattern.
    #[arg(long = "filter-no-match-test", visible_alias = "fnmt", value_name = "REGEX")]
    pub filter_test_pattern_inverse: Option<regex::Regex>,

    /// Only run tests in contracts matching the specified regex pattern.
    #[arg(long = "filter-match-contract", visible_alias = "fmc", value_name = "REGEX")]
    pub filter_contract_pattern: Option<regex::Regex>,

    /// Only run tests in contracts that do not match the specified regex pattern.
    #[arg(long = "filter-no-match-contract", visible_alias = "fnmc", value_name = "REGEX")]
    pub filter_contract_pattern_inverse: Option<regex::Regex>,

    /// Only run tests in source files matching the specified glob pattern.
    #[arg(long = "filter-match-path", visible_alias = "fmp", value_name = "GLOB")]
    pub filter_path_pattern: Option<GlobMatcher>,

    /// Only run tests in source files that do not match the specified glob pattern.
    #[arg(
        id = "filter-no-match-path",
        long = "filter-no-match-path",
        visible_alias = "fnmp",
        value_name = "GLOB"
    )]
    pub filter_path_pattern_inverse: Option<GlobMatcher>,

    /// Only show coverage for files that do not match the specified regex pattern.
    #[arg(long = "filter-no-match-coverage", visible_alias = "fnmco", value_name = "REGEX")]
    pub filter_coverage_pattern_inverse: Option<regex::Regex>,
}

impl CustomFilterArgs {
    /// Returns true if the filter is empty.
    pub fn is_empty(&self) -> bool {
        self.filter_test_pattern.is_none() &&
            self.filter_test_pattern_inverse.is_none() &&
            self.filter_contract_pattern.is_none() &&
            self.filter_contract_pattern_inverse.is_none() &&
            self.filter_path_pattern.is_none() &&
            self.filter_path_pattern_inverse.is_none()
    }

    /// Merges the set filter globs with the config's values
    pub fn merge_with_config(mut self, config: &Config) -> ProjectPathsAwareFilter {
        if self.filter_test_pattern.is_none() {
            self.filter_test_pattern = config.test_pattern.clone().map(Into::into);
        }
        if self.filter_test_pattern_inverse.is_none() {
            self.filter_test_pattern_inverse = config.test_pattern_inverse.clone().map(Into::into);
        }
        if self.filter_contract_pattern.is_none() {
            self.filter_contract_pattern = config.contract_pattern.clone().map(Into::into);
        }
        if self.filter_contract_pattern_inverse.is_none() {
            self.filter_contract_pattern_inverse = config.contract_pattern_inverse.clone().map(Into::into);
        }
        if self.filter_path_pattern.is_none() {
            self.filter_path_pattern = config.path_pattern.clone().map(Into::into);
        }
        if self.filter_path_pattern_inverse.is_none() {
            self.filter_path_pattern_inverse = config.path_pattern_inverse.clone().map(Into::into);
        }
        if self.filter_coverage_pattern_inverse.is_none() {
            self.filter_coverage_pattern_inverse = config.coverage_pattern_inverse.clone().map(Into::into);
        }
        ProjectPathsAwareFilter { args_filter: self, paths: config.project_paths() }
    }
}

impl fmt::Debug for CustomFilterArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFilterArgs")
            .field("filter-match-test", &self.filter_test_pattern.as_ref().map(|r| r.as_str()))
            .field("filter-no-match-test", &self.filter_test_pattern_inverse.as_ref().map(|r| r.as_str()))
            .field("filter-match-contract", &self.filter_contract_pattern.as_ref().map(|r| r.as_str()))
            .field("filter-no-match-contract", &self.filter_contract_pattern_inverse.as_ref().map(|r| r.as_str()))
            .field("filter-match-path", &self.filter_path_pattern.as_ref().map(|g| g.as_str()))
            .field("filter-no-match-path", &self.filter_path_pattern_inverse.as_ref().map(|g| g.as_str()))
            .field("filter-no-match-coverage", &self.filter_coverage_pattern_inverse.as_ref().map(|g| g.as_str()))
            .finish_non_exhaustive()
    }
}

impl FileFilter for CustomFilterArgs {
    /// Returns true if the file regex pattern match the `file`
    ///
    /// If no file regex is set this returns true by default
    fn is_match(&self, file: &Path) -> bool {
        self.matches_path(file)
    }
}

impl TestFilter for CustomFilterArgs {
    fn matches_test(&self, test_name: &str) -> bool {
        let mut ok = true;
        if let Some(re) = &self.filter_test_pattern {
            ok = ok && re.is_match(test_name);
        }
        if let Some(re) = &self.filter_test_pattern_inverse {
            ok = ok && !re.is_match(test_name);
        }
        ok
    }

    fn matches_contract(&self, contract_name: &str) -> bool {
        let mut ok = true;
        if let Some(re) = &self.filter_contract_pattern {
            ok = ok && re.is_match(contract_name);
        }
        if let Some(re) = &self.filter_contract_pattern_inverse {
            ok = ok && !re.is_match(contract_name);
        }
        ok
    }

    fn matches_path(&self, path: &Path) -> bool {
        let mut ok = true;
        if let Some(re) = &self.filter_path_pattern {
            ok = ok && re.is_match(path);
        }
        if let Some(re) = &self.filter_path_pattern_inverse {
            ok = ok && !re.is_match(path);
        }
        ok
    }
}

impl fmt::Display for CustomFilterArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(p) = &self.filter_test_pattern {
            writeln!(f, "\tfilter-match-test: `{}`", p.as_str())?;
        }
        if let Some(p) = &self.filter_test_pattern_inverse {
            writeln!(f, "\tfilter-no-match-test: `{}`", p.as_str())?;
        }
        if let Some(p) = &self.filter_contract_pattern {
            writeln!(f, "\tfilter-match-contract: `{}`", p.as_str())?;
        }
        if let Some(p) = &self.filter_contract_pattern_inverse {
            writeln!(f, "\tfilter-no-match-contract: `{}`", p.as_str())?;
        }
        if let Some(p) = &self.filter_path_pattern {
            writeln!(f, "\tfilter-match-path: `{}`", p.as_str())?;
        }
        if let Some(p) = &self.filter_path_pattern_inverse {
            writeln!(f, "\tfilter-no-match-path: `{}`", p.as_str())?;
        }
        if let Some(p) = &self.filter_coverage_pattern_inverse {
            writeln!(f, "\tfilter-no-match-coverage: `{}`", p.as_str())?;
        }
        Ok(())
    }
}

/// A filter that combines all command line arguments and the paths of the current projects
#[derive(Clone, Debug)]
pub struct ProjectPathsAwareFilter {
    args_filter: CustomFilterArgs,
    paths: ProjectPathsConfig,
}

impl ProjectPathsAwareFilter {
    /// Returns true if the filter is empty.
    pub fn is_empty(&self) -> bool {
        self.args_filter.is_empty()
    }

    /// Returns the CLI arguments.
    pub fn args(&self) -> &CustomFilterArgs {
        &self.args_filter
    }

    /// Returns the CLI arguments mutably.
    pub fn args_mut(&mut self) -> &mut CustomFilterArgs {
        &mut self.args_filter
    }

    /// Returns the project paths.
    pub fn paths(&self) -> &ProjectPathsConfig {
        &self.paths
    }
}

impl FileFilter for ProjectPathsAwareFilter {
    /// Returns true if the file regex pattern match the `file`
    ///
    /// If no file regex is set this returns true by default
    fn is_match(&self, mut file: &Path) -> bool {
        file = file.strip_prefix(&self.paths.root).unwrap_or(file);
        self.args_filter.is_match(file)
    }
}

impl TestFilter for ProjectPathsAwareFilter {
    fn matches_test(&self, test_name: &str) -> bool {
        self.args_filter.matches_test(test_name)
    }

    fn matches_contract(&self, contract_name: &str) -> bool {
        self.args_filter.matches_contract(contract_name)
    }

    fn matches_path(&self, mut path: &Path) -> bool {
        // we don't want to test files that belong to a library
        path = path.strip_prefix(&self.paths.root).unwrap_or(path);
        self.args_filter.matches_path(path) && !self.paths.has_library_ancestor(path)
    }
}

impl fmt::Display for ProjectPathsAwareFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.args_filter.fmt(f)
    }
}
