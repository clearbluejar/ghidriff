"use strict";(self.webpackChunkwww=self.webpackChunkwww||[]).push([[7122],{7146:(i,e,n)=>{n.r(e),n.d(e,{assets:()=>a,contentTitle:()=>c,default:()=>h,frontMatter:()=>l,metadata:()=>d,toc:()=>o});var t=n(5893),s=n(1151);const l={description:"Social Diffing with ghidriff - Github, GitLab, READMEs, Diffpreview.github.io",image:"/img/social-diffing.png"},c=void 0,d={id:"Social Diffing/Social Diffing",title:"Social Diffing",description:"Social Diffing with ghidriff - Github, GitLab, READMEs, Diffpreview.github.io",source:"@site/docs/Social Diffing/Social Diffing.md",sourceDirName:"Social Diffing",slug:"/Social Diffing/",permalink:"/ghidriff/docs/Social Diffing/",draft:!1,unlisted:!1,editUrl:"https://github.com/clearbluejar/ghidriff/tree/main/www/docs/docs/Social Diffing/Social Diffing.md",tags:[],version:"current",frontMatter:{description:"Social Diffing with ghidriff - Github, GitLab, READMEs, Diffpreview.github.io",image:"/img/social-diffing.png"},sidebar:"tutorialSidebar",previous:{title:"Diffing the Windows Kernel",permalink:"/ghidriff/docs/guides/Diffing the Windows Kernel"}},a={},o=[{value:"Sample Diffs",id:"sample-diffs",level:3},{value:"Github",id:"github",level:2},{value:"Gists",id:"gists",level:3},{value:"READMEs",id:"readmes",level:3},{value:"Posting to a Github Gist",id:"posting-to-a-github-gist",level:2},{value:"Option 1: Post using <code>gh</code> client",id:"option-1-post-using-gh-client",level:3},{value:"Option 2: Copy/Paste Markdown to new gist",id:"option-2-copypaste-markdown-to-new-gist",level:3},{value:"Publishing on a blog",id:"publishing-on-a-blog",level:2},{value:"Tweet with deep links",id:"tweet-with-deep-links",level:2}];function r(i){const e={a:"a",code:"code",div:"div",h2:"h2",h3:"h3",img:"img",li:"li",p:"p",pre:"pre",ul:"ul",...(0,s.a)(),...i.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsxs)(e.p,{children:[(0,t.jsx)(e.img,{alt:"Alt text",src:n(8519).Z+"",width:"1200",height:"628"}),"\nAs the diff output of ",(0,t.jsx)(e.code,{children:"ghidriff"})," is markdown, it can be shared almost anywhere."]}),"\n",(0,t.jsx)(e.h3,{id:"sample-diffs",children:"Sample Diffs"}),"\n",(0,t.jsxs)(e.div,{children:["\n    ",(0,t.jsx)(e.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282",children:(0,t.jsx)(e.img,{width:"30%",align:"top",alt:"image",src:"https://github.com/clearbluejar/ghidriff/assets/3752074/d53b681f-8cc9-479c-af4c-5ec697cf4989"})}),"\n    ",(0,t.jsx)(e.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#visual-chart-diff",children:(0,t.jsx)(e.img,{width:"30%",align:"top",alt:"image",src:"https://github.com/clearbluejar/ghidriff/assets/3752074/16d7ae4c-4df9-4bcd-b4af-0ce576d49ad1"})}),"\n",(0,t.jsxs)(e.div,{children:["\n",(0,t.jsx)(e.h2,{id:"github",children:"Github"}),"\n",(0,t.jsx)(e.h3,{id:"gists",children:"Gists"}),"\n",(0,t.jsxs)(e.ul,{children:["\n",(0,t.jsxs)(e.li,{children:["Host your recent diff in a GitHub gist: ",(0,t.jsx)(e.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282",children:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282"})]}),"\n",(0,t.jsxs)(e.li,{children:["Deep link to interesting\n",(0,t.jsxs)(e.ul,{children:["\n",(0,t.jsxs)(e.li,{children:["functions\n",(0,t.jsxs)(e.ul,{children:["\n",(0,t.jsx)(e.li,{children:(0,t.jsx)(e.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#cmrenamekey",children:"CnRenameKey"})}),"\n"]}),"\n"]}),"\n",(0,t.jsxs)(e.li,{children:["command-line\n",(0,t.jsxs)(e.ul,{children:["\n",(0,t.jsx)(e.li,{children:(0,t.jsx)(e.a,{href:"https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#command-line",children:"ghidriff command line"})}),"\n"]}),"\n"]}),"\n"]}),"\n"]}),"\n"]}),"\n",(0,t.jsx)(e.h3,{id:"readmes",children:"READMEs"}),"\n",(0,t.jsx)(e.h2,{id:"posting-to-a-github-gist",children:"Posting to a Github Gist"}),"\n",(0,t.jsxs)(e.p,{children:["After you create you diff it will be located in ",(0,t.jsx)(e.code,{children:"ghidriffs/diff.md"}),"."]}),"\n",(0,t.jsxs)(e.h3,{id:"option-1-post-using-gh-client",children:["Option 1: Post using ",(0,t.jsx)(e.code,{children:"gh"})," client"]}),"\n",(0,t.jsxs)(e.p,{children:[(0,t.jsx)(e.code,{children:"cat"})," to ",(0,t.jsx)(e.code,{children:"stdin"}),":"]}),"\n",(0,t.jsx)(e.pre,{children:(0,t.jsx)(e.code,{className:"language-bash",children:"cat ghidriff.md | gh gist create -f ghidriff.gist.filename.md -\n"})}),"\n",(0,t.jsx)(e.h3,{id:"option-2-copypaste-markdown-to-new-gist",children:"Option 2: Copy/Paste Markdown to new gist"}),"\n",(0,t.jsxs)(e.p,{children:["Just copy paste to new file and make sure to set the filetype to ",(0,t.jsx)(e.code,{children:"md"}),"."]}),"\n",(0,t.jsx)(e.h2,{id:"publishing-on-a-blog",children:"Publishing on a blog"}),"\n",(0,t.jsx)(e.p,{children:"See some of the samples posted in the diffs(/diffs). If the blog enginer can render markdown, it should work."}),"\n",(0,t.jsx)(e.h2,{id:"tweet-with-deep-links",children:"Tweet with deep links"})]})]})]})}function h(i={}){const{wrapper:e}={...(0,s.a)(),...i.components};return e?(0,t.jsx)(e,{...i,children:(0,t.jsx)(r,{...i})}):r(i)}},8519:(i,e,n)=>{n.d(e,{Z:()=>t});const t=n.p+"assets/images/social-diffing-f24e6f2b9f75a8fd457729d4aaff13b3.png"},1151:(i,e,n)=>{n.d(e,{Z:()=>d,a:()=>c});var t=n(7294);const s={},l=t.createContext(s);function c(i){const e=t.useContext(l);return t.useMemo((function(){return"function"==typeof i?i(e):{...e,...i}}),[e,i])}function d(i){let e;return e=i.disableParentContext?"function"==typeof i.components?i.components(s):i.components||s:c(i.components),t.createElement(l.Provider,{value:e},i.children)}}}]);