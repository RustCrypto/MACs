use belt_mac::BeltMac;
use digest::new_resettable_mac_test;

new_resettable_mac_test!(belt_mac_stb, "belt-mac", BeltMac, "left");
