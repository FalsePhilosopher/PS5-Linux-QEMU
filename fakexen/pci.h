#pragma once

extern uint64_t pci_cfg_bases[256];

volatile uint32_t* pci_find_capability(int bus, int dev, int fn, int which);
