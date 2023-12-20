---
description: Social Diffing with ghidriff - Github, GitLab, READMEs, Diffpreview.github.io
image: /static/img/social-diffing.png
---

![Alt text](../../static/img/social-diffing.png)
As the diff output of `ghidriff` is markdown, it can be shared almost anywhere.

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

See some of the samples posted in the diffs(/diffs). If the blog enginer can render markdown, it should work.


## Tweet with deep links
