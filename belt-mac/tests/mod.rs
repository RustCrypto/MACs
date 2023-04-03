use digest::new_resettable_mac_test;
use belt_mac::BeltMac;

new_resettable_mac_test!(belt_mac_stb, "belt-mac", BeltMac, "left");