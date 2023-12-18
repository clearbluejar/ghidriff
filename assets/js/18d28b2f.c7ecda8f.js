"use strict";(self.webpackChunkwww=self.webpackChunkwww||[]).push([[4363],{8013:(e,i,n)=>{n.r(i),n.d(i,{assets:()=>a,contentTitle:()=>l,default:()=>h,frontMatter:()=>d,metadata:()=>t,toc:()=>c});var s=n(5893),r=n(1151);const d={sidebar_position:1},l=void 0,t={id:"README/High Level",title:"High Level",description:"Sample Diffs",source:"@site/docs/README/High Level.md",sourceDirName:"README",slug:"/README/High Level",permalink:"/ghidriff/docs/README/High Level",draft:!1,unlisted:!1,editUrl:"https://github.com/clearbluejar/ghidriff/tree/main/www/docs/docs/README/High Level.md",tags:[],version:"current",sidebarPosition:1,frontMatter:{sidebar_position:1},sidebar:"tutorialSidebar",previous:{title:"README",permalink:"/ghidriff/docs/category/readme"},next:{title:"Engine",permalink:"/ghidriff/docs/README/Engine"}},a={},c=[{value:"Sample Diffs",id:"sample-diffs",level:3},{value:"Features",id:"features",level:3},{value:"Design Goals",id:"design-goals",level:3},{value:"Powered by Ghidra",id:"powered-by-ghidra",level:3}];function o(e){const i={a:"a",code:"code",div:"div",h3:"h3",img:"img",li:"li",mermaid:"mermaid",p:"p",ul:"ul",...(0,r.a)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(i.mermaid,{value:"flowchart LR\n\na(old binary - rpcrt4.dll-v1) --\x3e b[GhidraDiffEngine]\nc(new binary - rpcrt4.dll-v2) --\x3e b\n\nb --\x3e e(Ghidra Project Files)\nb --\x3e diffs_output_dir\n\nsubgraph diffs_output_dir\n    direction LR\n    i(rpcrt4.dll-v1-v2.diff.md)\n    h(rpcrt4.dll-v1-v2.diff.json)\n    j(rpcrt4.dll-v1-v2.diff.side-by-side.html)\nend"}),"\n",(0,s.jsx)(i.h3,{id:"sample-diffs",children:"Sample Diffs"}),"\n",(0,s.jsxs)(i.div,{children:["\n    ",(0,s.jsx)(i.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282",children:(0,s.jsx)(i.img,{width:"30%",align:"top",alt:"image",src:"https://github.com/clearbluejar/ghidriff/assets/3752074/d53b681f-8cc9-479c-af4c-5ec697cf4989"})}),"\n    ",(0,s.jsx)(i.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#visual-chart-diff",children:(0,s.jsx)(i.img,{width:"30%",align:"top",alt:"image",src:"https://github.com/clearbluejar/ghidriff/assets/3752074/16d7ae4c-4df9-4bcd-b4af-0ce576d49ad1"})}),"\n    ",(0,s.jsx)(i.a,{href:"https://diffpreview.github.io/?f6fecbc507a9f1a92c9231e3db7ef40d",children:(0,s.jsx)(i.img,{width:"30%",align:"top",src:"https://github.com/clearbluejar/ghidriff/assets/3752074/662ed834-738d-4be1-96c3-8500ccab9591"})}),"\n",(0,s.jsxs)(i.div,{children:["\n",(0,s.jsx)(i.h3,{id:"features",children:"Features"}),"\n",(0,s.jsxs)(i.ul,{children:["\n",(0,s.jsx)(i.li,{children:"Command Line (patch diffing workflow reduced to a single step)"}),"\n",(0,s.jsx)(i.li,{children:"Highlights important changes in the TOC"}),"\n",(0,s.jsx)(i.li,{children:"Fast - Can diff the full Windows kernel in less than a minute (after Ghidra analysis is complete)"}),"\n",(0,s.jsxs)(i.li,{children:["Enables Social Diffing\n",(0,s.jsxs)(i.ul,{children:["\n",(0,s.jsx)(i.li,{children:"Beautiful Markdown Output"}),"\n",(0,s.jsx)(i.li,{children:"Easily hosted in a GitHub or GitLab gist, blog, or anywhere markdown is supported"}),"\n",(0,s.jsx)(i.li,{children:"Visual Diff Graph Results"}),"\n"]}),"\n"]}),"\n",(0,s.jsx)(i.li,{children:"Supports both unified and side by side diff results (unified is default)"}),"\n",(0,s.jsxs)(i.li,{children:["Provides unique Meta Diffs:\n",(0,s.jsxs)(i.ul,{children:["\n",(0,s.jsx)(i.li,{children:"Binary Strings"}),"\n",(0,s.jsx)(i.li,{children:"Called"}),"\n",(0,s.jsx)(i.li,{children:"Calling"}),"\n",(0,s.jsx)(i.li,{children:"Binary Metadata"}),"\n"]}),"\n"]}),"\n",(0,s.jsxs)(i.li,{children:["Batteries Included\n",(0,s.jsxs)(i.ul,{children:["\n",(0,s.jsx)(i.li,{children:"Docker support"}),"\n",(0,s.jsx)(i.li,{children:"Automated Testing"}),"\n",(0,s.jsx)(i.li,{children:"Ghidra (No license required)"}),"\n"]}),"\n"]}),"\n"]}),"\n",(0,s.jsxs)(i.p,{children:["See below for ",(0,s.jsx)(i.a,{href:"#sample-usage",children:"CVE diffs and sample usage"})]}),"\n",(0,s.jsx)(i.h3,{id:"design-goals",children:"Design Goals"}),"\n",(0,s.jsxs)(i.ul,{children:["\n",(0,s.jsx)(i.li,{children:"Find all added, deleted, and modified functions"}),"\n",(0,s.jsx)(i.li,{children:"Provide foundation for automation"}),"\n",(0,s.jsx)(i.li,{children:"Simple, Fast, Accurate"}),"\n",(0,s.jsx)(i.li,{children:"Resilient"}),"\n",(0,s.jsx)(i.li,{children:"Extendable"}),"\n",(0,s.jsx)(i.li,{children:"Easy sharing of results"}),"\n",(0,s.jsx)(i.li,{children:"Social Diffing"}),"\n"]}),"\n",(0,s.jsx)(i.h3,{id:"powered-by-ghidra",children:"Powered by Ghidra"}),"\n",(0,s.jsxs)(i.p,{children:["The heavy lifting of the binary analysis is done by Ghidra and the diffing is possible via Ghidra's Program API.  ",(0,s.jsx)(i.code,{children:"ghidriff"})," provides a diffing ",(0,s.jsx)(i.a,{href:"#engine",children:"workflow"}),", function matching, and resulting markdown and HTML diff output."]})]})]})]})}function h(e={}){const{wrapper:i}={...(0,r.a)(),...e.components};return i?(0,s.jsx)(i,{...e,children:(0,s.jsx)(o,{...e})}):o(e)}},1151:(e,i,n)=>{n.d(i,{Z:()=>t,a:()=>l});var s=n(7294);const r={},d=s.createContext(r);function l(e){const i=s.useContext(d);return s.useMemo((function(){return"function"==typeof e?e(i):{...i,...e}}),[i,e])}function t(e){let i;return i=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:l(e.components),s.createElement(d.Provider,{value:i},e.children)}}}]);