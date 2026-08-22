# Commercial licence

Lynceus is dual-licensed.

**Option 1: AGPL-3.0-or-later.** Free, and what you get by default. Use it,
run it, modify it, redistribute it, sell it. The condition is reciprocity:
anyone you convey it to gets the same freedoms and the corresponding source,
and that includes anyone who only ever interacts with it *over a network*.
That network clause is the part AGPL adds over plain GPL. Run a modified
Lynceus as a service and your users are entitled to that modified source. See
[LICENSE](LICENSE) for the terms that actually bind; this file is a summary
and the licence text wins wherever the two differ.

**Option 2: a commercial licence.** If you want to build Lynceus into a
closed-source product, ship it inside a proprietary appliance, or run a
modified version as a service without publishing your changes, buy a licence
and the reciprocity obligations are lifted for you.

## Who needs option 2

You need a commercial licence if any of these is true:

- you distribute a product containing Lynceus, in whole or in part, and cannot
  or will not release your own source under AGPL-3.0
- you run a modified Lynceus as a network service and will not offer that
  modified source to its users
- your legal or procurement process forbids copyleft dependencies

You do **not** need one to use Lynceus unmodified, to modify it for your own
internal use without conveying it to anyone, or to contribute changes back.

## Contact

Kev Wilson, <kev@gurutechnology.services>

Say what you want to build and how you intend to distribute it. Terms are
per-case; there is no published price list.

## Why this arrangement

Sole copyright is what makes dual licensing possible at all: a project that has
taken patches from contributors without a CLA cannot relicense them, and cannot
offer anyone an exemption from a licence it does not wholly own. Every commit in
this repository is authored by one copyright holder. See
[`.mailmap`](.mailmap), which canonicalises the several author strings the
history was written under, and verify it with:

```sh
git log --format='%aN <%aE>' | sort -u
```

One line out means one copyright holder.

## What this does not do

- **It is not retroactive.** Every release up to and including v0.9.5 was
  published under MIT. Those rights are irrevocable for those versions. AGPL
  applies from the relicensing commit onward.
- **It does not change the dependencies.** Lynceus's runtime dependency closure
  is MIT, BSD-3-Clause, Apache-2.0, MPL-2.0 and PSF-2.0. All are compatible
  with AGPL-3.0 and none is copyleft-incompatible. The vendored Pico CSS keeps its own MIT
  licence.
- **It does not make the project a company.** This is a one-person hobby
  project. A commercial licence buys you the licence, not a support contract or
  an SLA.
