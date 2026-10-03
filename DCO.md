# Developer Certificate of Origin

Every commit contributed to Chitala OS carries a `Signed-off-by` line from its author. With it, the author certifies the Developer Certificate of Origin 1.1 below.

Contributions are licensed under the project license (Apache-2.0). Section 5 of that license makes this the default for contributions submitted for inclusion. The sign-off adds a record that you had the right to submit the change.

## How to sign off

```bash
git commit -s -m "Explain the change"
```

This appends `Signed-off-by: Your Name <you@example.com>`, using your `git config user.name` and `user.email`. Use the same name and email as the commit's author: the CI check "DCO sign-off" compares them. To sign off commits you already made, run `git rebase --signoff <base>` and force-push your branch.

Notes:

- Sign off with a name you are known by. If you contribute on behalf of an employer, make sure you are allowed to.
- Tools, including AI assistants, may help you write a change, but **you** sign off. You remain responsible for having the right to submit it under the license.
- Commits from automation such as Dependabot are exempt.

## The certificate

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Source: <https://developercertificate.org/>
