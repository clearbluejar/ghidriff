---
description: "BSIM: Ghidra Binary Similarity"
image: /img/ghidriff-BSIM.jpeg
---

![ghidriff BSIM](../../static/img/ghidriff-BSIM.jpeg)

## Background

With the introduction of BSIM in Ghidra 11.0 a new power has been brought to `ghidriff`.

> The BSim Program Correlator uses the decompiler to generate confidence scores between potentially matching functions in the source and destination programs. Function call-graphs are used to further boost the scores and distinguish between conflicting matches.
> 
> The decompiler generates a formal feature vector for a function, where individual features are extracted from the control-flow and data-flow characteristics of its normalized p-code representation.

> Functions are compared by comparing their corresponding feature vectors, from which similarity and confidence scores are extracted.

> A confidence score, for this correlator, is an open-ended floating-point value (ranging from -infinity to +infinity) describing the amount of correspondence between the control-flow and data-flow of two functions. A good working range for setting thresholds (below) and for describing function pairs with some matching features is 0.0 to 100.0. A score of 0.0 corresponds to functions with roughly equal amounts of similar and dissimilar features. A score of 10.0 is typical for small identical functions, and 100.0 is achieved by pairs of larger sized identical functions.
> [Ghidra BSIM Docs](https://github.com/NationalSecurityAgency/ghidra/blob/bd76ec5fc8917699d0f10e9afeff088d30f2f4fa/Ghidra/Features/VersionTrackingBSim/src/main/help/help/topics/BSimCorrelator/BSim_Correlator.html)


## BSIM correlator first impressions
- The BSIM correlator is great for matching. The overall improvement for #ghidriff is a net plus, but some custom #ghidriff correlators were already providing similar structural matching (not as good, but similar) 💪
- Speculation: 🧐 BSIM is the reason why Ghidra Version Tracking was lacking structural matching heuristics. This is why ghidriff has its own [structural function matching](https://github.com/clearbluejar/ghidriff/blob/main/ghidriff/correlators.py#L14-L103). BSIM is a more accurate and powerful version. 
- Adding BSIM to #ghidriff slows it down a bit. This is because BSIM decompiles all functions to match based on data flow and call graphs, and #ghidriff similarly already does this to make matching decisions. It has been optimized. 🤓 

## ghidriff BSIM correlations options

```bash
BSIM Options:
  --bsim, --no-bsim     Toggle using BSIM correlation (default: True)
  --bsim-full, --no-bsim-full
                        Slower but better matching. Use only when needed (default: False)
```

You can run ghidriff with or without BSIM.  My recommendation is to run with.  The `--bsim-full` will allow you to match with BSIM across the full address space. It is generally recommended not to run full, but might be worth a try if you have a complicated diff as BSIM might pick up some new matches.