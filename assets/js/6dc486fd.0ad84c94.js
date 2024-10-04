"use strict";(self.webpackChunkwww=self.webpackChunkwww||[]).push([[5880],{7636:(i,e,r)=>{r.r(e),r.d(e,{assets:()=>c,contentTitle:()=>s,default:()=>h,frontMatter:()=>o,metadata:()=>a,toc:()=>l});var n=r(4848),t=r(8453);const o={description:"BSIM: Ghidra Binary Similarity",image:"/img/ghidriff-BSIM.jpeg"},s=void 0,a={id:"BSIM/Binary-Similarity-BSIM",title:"Binary-Similarity-BSIM",description:"BSIM: Ghidra Binary Similarity",source:"@site/docs/BSIM/Binary-Similarity-BSIM.md",sourceDirName:"BSIM",slug:"/BSIM/Binary-Similarity-BSIM",permalink:"/ghidriff/docs/BSIM/Binary-Similarity-BSIM",draft:!1,unlisted:!1,editUrl:"https://github.com/clearbluejar/ghidriff/tree/main/www/docs/docs/BSIM/Binary-Similarity-BSIM.md",tags:[],version:"current",frontMatter:{description:"BSIM: Ghidra Binary Similarity",image:"/img/ghidriff-BSIM.jpeg"},sidebar:"tutorialSidebar",previous:{title:"Diffing the Windows Kernel",permalink:"/ghidriff/docs/guides/Diffing the Windows Kernel"},next:{title:"Social Diffing",permalink:"/ghidriff/docs/Social Diffing/"}},c={},l=[{value:"Background",id:"background",level:2},{value:"BSIM correlator first impressions",id:"bsim-correlator-first-impressions",level:2},{value:"ghidriff BSIM correlations options",id:"ghidriff-bsim-correlations-options",level:2}];function d(i){const e={a:"a",blockquote:"blockquote",code:"code",h2:"h2",img:"img",li:"li",p:"p",pre:"pre",ul:"ul",...(0,t.R)(),...i.components};return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsx)(e.p,{children:(0,n.jsx)(e.img,{alt:"ghidriff BSIM",src:r(8553).A+"",width:"1024",height:"1024"})}),"\n",(0,n.jsx)(e.h2,{id:"background",children:"Background"}),"\n",(0,n.jsxs)(e.p,{children:["With the introduction of BSIM in Ghidra 11.0 a new power has been brought to ",(0,n.jsx)(e.code,{children:"ghidriff"}),"."]}),"\n",(0,n.jsxs)(e.blockquote,{children:["\n",(0,n.jsx)(e.p,{children:"The BSim Program Correlator uses the decompiler to generate confidence scores between potentially matching functions in the source and destination programs. Function call-graphs are used to further boost the scores and distinguish between conflicting matches."}),"\n",(0,n.jsx)(e.p,{children:"The decompiler generates a formal feature vector for a function, where individual features are extracted from the control-flow and data-flow characteristics of its normalized p-code representation."}),"\n"]}),"\n",(0,n.jsxs)(e.blockquote,{children:["\n",(0,n.jsx)(e.p,{children:"Functions are compared by comparing their corresponding feature vectors, from which similarity and confidence scores are extracted."}),"\n"]}),"\n",(0,n.jsxs)(e.blockquote,{children:["\n",(0,n.jsxs)(e.p,{children:["A confidence score, for this correlator, is an open-ended floating-point value (ranging from -infinity to +infinity) describing the amount of correspondence between the control-flow and data-flow of two functions. A good working range for setting thresholds (below) and for describing function pairs with some matching features is 0.0 to 100.0. A score of 0.0 corresponds to functions with roughly equal amounts of similar and dissimilar features. A score of 10.0 is typical for small identical functions, and 100.0 is achieved by pairs of larger sized identical functions.\n",(0,n.jsx)(e.a,{href:"https://github.com/NationalSecurityAgency/ghidra/blob/bd76ec5fc8917699d0f10e9afeff088d30f2f4fa/Ghidra/Features/VersionTrackingBSim/src/main/help/help/topics/BSimCorrelator/BSim_Correlator.html",children:"Ghidra BSIM Docs"})]}),"\n"]}),"\n",(0,n.jsx)(e.h2,{id:"bsim-correlator-first-impressions",children:"BSIM correlator first impressions"}),"\n",(0,n.jsxs)(e.ul,{children:["\n",(0,n.jsx)(e.li,{children:"The BSIM correlator is great for matching. The overall improvement for #ghidriff is a net plus, but some custom #ghidriff correlators were already providing similar structural matching (not as good, but similar) \ud83d\udcaa"}),"\n",(0,n.jsxs)(e.li,{children:["Speculation: \ud83e\uddd0 BSIM is the reason why Ghidra Version Tracking was lacking structural matching heuristics. This is why ghidriff has its own ",(0,n.jsx)(e.a,{href:"https://github.com/clearbluejar/ghidriff/blob/main/ghidriff/correlators.py#L14-L103",children:"structural function matching"}),". BSIM is a more accurate and powerful version."]}),"\n",(0,n.jsx)(e.li,{children:"Adding BSIM to #ghidriff slows it down a bit. This is because BSIM decompiles all functions to match based on data flow and call graphs, and #ghidriff similarly already does this to make matching decisions. It has been optimized. \ud83e\udd13"}),"\n"]}),"\n",(0,n.jsx)(e.h2,{id:"ghidriff-bsim-correlations-options",children:"ghidriff BSIM correlations options"}),"\n",(0,n.jsx)(e.pre,{children:(0,n.jsx)(e.code,{className:"language-bash",children:"BSIM Options:\n  --bsim, --no-bsim     Toggle using BSIM correlation (default: True)\n  --bsim-full, --no-bsim-full\n                        Slower but better matching. Use only when needed (default: False)\n"})}),"\n",(0,n.jsxs)(e.p,{children:["You can run ghidriff with or without BSIM.  My recommendation is to run with.  The ",(0,n.jsx)(e.code,{children:"--bsim-full"})," will allow you to match with BSIM across the full address space. It is generally recommended not to run full, but might be worth a try if you have a complicated diff as BSIM might pick up some new matches."]})]})}function h(i={}){const{wrapper:e}={...(0,t.R)(),...i.components};return e?(0,n.jsx)(e,{...i,children:(0,n.jsx)(d,{...i})}):d(i)}},8553:(i,e,r)=>{r.d(e,{A:()=>n});const n=r.p+"assets/images/ghidriff-BSIM-20972c28dd6cb53afe828da87f9096e9.jpeg"},8453:(i,e,r)=>{r.d(e,{R:()=>s,x:()=>a});var n=r(6540);const t={},o=n.createContext(t);function s(i){const e=n.useContext(o);return n.useMemo((function(){return"function"==typeof i?i(e):{...e,...i}}),[e,i])}function a(i){let e;return e=i.disableParentContext?"function"==typeof i.components?i.components(t):i.components||t:s(i.components),n.createElement(o.Provider,{value:e},i.children)}}}]);