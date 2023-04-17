use std::collections::hash_map::Values;
use std::collections::HashMap;
use std::fmt::{self, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use sazanami_proto::parse_cidr_v4;
use sazanami_proto::{Ipv4Address, Ipv4Cidr};
use sazanami_ringo::HashRing;
use sazanami_ringo::Node;
use serde::Deserialize;

#[derive(Debug, Clone)]
struct Server(String);

impl Node for Server {
    fn hash_key(&self) -> String {
        self.0.clone()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupType {
    Select,
    LoadBalance,
    Chain,
}

#[derive(Clone, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(alias = "type")]
    pub type_: GroupType,
    pub proxies: Vec<String>,
    #[serde(skip_deserializing)]
    candidates: Option<HashRing<Server, md5::Md5>>,
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Group")
            .field("name", &self.name)
            .field("type", &self.type_)
            .field("proxies", &self.proxies)
            .finish()
    }
}

impl Group {
    pub fn init(&mut self) {
        let mut candidates = HashRing::new();
        for proxy in self.proxies.iter() {
            candidates.add(&Server(proxy.clone()), 1);
        }

        self.candidates = Some(candidates);
    }
    pub fn select_proxy(&self, ident: &str) -> Option<String> {
        let candidates = self.candidates.as_ref().expect("group is not initialized");
        candidates.get_str(ident).map(|x| x.0.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyGroups {
    groups: Arc<HashMap<String, Group>>,
}

impl Default for ProxyGroups {
    fn default() -> Self {
        Self::new(vec![])
    }
}

impl ProxyGroups {
    pub fn new(mut groups: Vec<Group>) -> Self {
        for group in groups.iter_mut() {
            group.init();
        }
        let groups = HashMap::from_iter(groups.into_iter().map(|item| (item.name.clone(), item)));
        Self {
            groups: Arc::new(groups),
        }
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn get(&self, name: &str) -> Option<&Group> {
        self.groups.get(name)
    }

    pub fn has(&self, name: &str) -> bool {
        self.groups.get(name).is_some()
    }

    pub fn values(&self) -> Values<String, Group> {
        self.groups.values()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Rule {
    Domain(String, Action),
    DomainSuffix(String, Action),
    DomainKeyword(String, Action),
    IpCidr(Ipv4Cidr, Action),
    Match(Action),
}

#[derive(Eq, PartialEq, Clone, Debug, Hash, PartialOrd, Ord, Default)]
pub enum Action {
    #[default]
    Reject,
    Direct,
    Proxy,
    Probe,
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct ProxyRules {
    rules: Arc<Vec<Rule>>,
}

impl Default for ProxyRules {
    fn default() -> Self {
        Self::new(vec![])
    }
}

impl ProxyRules {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules: Arc::new(rules),
        }
    }

    // TODO: split to two function
    pub fn action_for_domain(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Option<Action> {
        let domain = domain.map(|s| s.trim_end_matches("."));
        let ip = ip.and_then(|ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        });
        let matched_rule = self.rules.iter().find(|rule| match (rule, domain, ip) {
            (Rule::Domain(d, _), Some(domain), _) if d == domain => true,
            (Rule::DomainSuffix(d, _), Some(domain), _) if domain.ends_with(d) => true,
            (Rule::DomainKeyword(d, _), Some(domain), _) if domain.contains(d) => true,
            (Rule::IpCidr(cidr, _), _, Some(ip)) => {
                let ip: Ipv4Address = ip.into();
                if cidr.contains_addr(&ip) {
                    return true;
                }
                false
            }
            (Rule::Match(_), ..) => true,
            _ => false,
        });
        matched_rule.map(|rule| match rule {
            Rule::Match(action) => action.clone(),
            Rule::Domain(_, action) => action.clone(),
            Rule::DomainSuffix(_, action) => action.clone(),
            Rule::DomainKeyword(_, action) => action.clone(),
            Rule::IpCidr(_, action) => action.clone(),
        })
    }

    pub fn prepend_rules(&mut self, rules: Vec<Rule>) {
        let rules_mut = Arc::make_mut(&mut self.rules);
        for rule in rules {
            rules_mut.insert(0, rule);
        }
    }

    pub fn default_action(&self) -> Action {
        Action::Direct
    }

    pub fn additional_cidrs(&self) -> Vec<Ipv4Cidr> {
        self.rules
            .iter()
            .filter_map(|rule| match rule {
                Rule::IpCidr(cidr, Action::Probe | Action::Proxy) => Some(*cidr),
                _ => None,
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn values(&self) -> Vec<Rule> {
        self.rules.to_vec()
    }
}

impl FromStr for Action {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "REJECT" => Action::Reject,
            "DIRECT" => Action::Direct,
            "PROXY" => Action::Proxy,
            "PROBE" => Action::Probe,
            s @ _ => Action::Custom(s.to_string()),
        })
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for Rule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let segments = s.splitn(3, ',').collect::<Vec<_>>();
        let (rule, criteria, action) = match segments.len() {
            2 => (segments[0], "", segments[1]),
            3 => (segments[0], segments[1], segments[2]),
            _ => unreachable!("{}", s),
        };

        Ok(match rule {
            "DOMAIN" => Rule::Domain(criteria.to_string(), Action::from_str(action).unwrap()),
            "DOMAIN-SUFFIX" => {
                Rule::DomainSuffix(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "DOMAIN-KEYWORD" => {
                Rule::DomainKeyword(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "IP-CIDR" => Rule::IpCidr(
                parse_cidr_v4(criteria.to_string()).unwrap(),
                Action::from_str(action).unwrap(),
            ),
            "MATCH" => Rule::Match(Action::from_str(action).unwrap()),
            _ => unreachable!(),
        })
    }
}
