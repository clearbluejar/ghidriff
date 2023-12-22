---
description: Social Diffing with ghidriff - Github, GitLab, READMEs, Diffpreview.github.io
image: /img/social-diffing.png
---

![Alt text](../../static/img/social-diffing.png)

> If GitHub can provide “social coding”, ghidriff can provide “social diffing”. Since the diff output is in markdown, you can publish the diff wherever markdown is supported. All the sections within the markdown are deep linked, which is great for sharing and pointing out specific areas of interest. - [Ghidriff Blog Post](https://clearbluejar.github.io/posts/ghidriff-ghidra-binary-diffing-engine/#social-binary-diffing)


### Sample Diffs

<div>
    <a href="https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282"><img width="30%" align=top alt="image" src="https://github.com/clearbluejar/ghidriff/assets/3752074/d53b681f-8cc9-479c-af4c-5ec697cf4989"></a>
    <a href="https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#visual-chart-diff"><img width="30%" align=top alt="image" src="https://github.com/clearbluejar/ghidriff/assets/3752074/16d7ae4c-4df9-4bcd-b4af-0ce576d49ad1"></a>
<div>


## Github

### Gists

- Host your recent diff in a GitHub gist: [https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282](https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282)
- Deep link to interesting 
  - functions
    - [CnRenameKey](https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#cmrenamekey)
  - command-line
    - [ghidriff command line](https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#command-line)


### READMEs

## Posting to a Github Gist

After you create you diff it will be located in `ghidriffs/diff.md`.

### Option 1: Post using `gh` client

`cat` to `stdin`:

```bash
cat ghidriff.md | gh gist create -f ghidriff.gist.filename.md -
```

### Option 2: Copy/Paste Markdown to new gist

Just copy paste to new file and make sure to set the filetype to `md`.

## Publishing on a blog

See some of the samples posted in the [diffs](/diffs/category/samples). If the blog enginer can render markdown, it should work.


## Tweet with deep links

> Here is an example of social diffing with CVE-2023-38140 from a recent post on Twitter. As each function is a deep-link, you can highlight (with deep-links) to the functions of interest. - [Ghidriff Blog Post](https://clearbluejar.github.io/posts/ghidriff-ghidra-binary-diffing-engine/#social-binary-diffing)
> [![](https://clearbluejar.github.io/assets/img/2023-12-20-ghidriff-ghidra-binary-diffing-engine/cve-2023-38140.png)](https://twitter.com/clearbluejar/status/1711613511367868845)




