# IWSpring2020

proto1.p4 -> uses exact matching. Assumes IP entry is the first entry in the DNS response answer. This does work in BMV2 currently.
proto2.p4 -> uses ternary matching. Able to parse variable number of CNAME entries that may precede an IP entry in a DNS response. This does not work in BMV2 currently due to ternary matching issues.