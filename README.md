# RECOVERABLE SECRETS

A standard for deterministic secure secrets recoverable by a single secret seed.

**Note**: This is an initial draft of the standard.

## Goals

- To make it easy to generate, recover and manage several types of secrets, such
  as passwords, GPG keys, ssh keys, among others.
- To restore all secrets, if lost, by backing up just the secret seed.

Informally, the goal of the standard is to broaden  the  scope  of  the  already
established standards defined by BIP-32, BIP-39, BIP-43 and  BIP-44,  which  are
standards for generating, managing and recovering the keys associated  with  BTC
addresses. Inspired by them, our goal is to make it more generic to manage other
types of secrets in different scenarios.

## Specification

We define a high-level abstract protocol for deterministic secrets derived  from
a single secret seed, without specifying the underlying technologies behind  it,
such as the cryptographic algorithms.

### Definitions

- **Seed**: static value used as a source of randomness to derive secrets.
- **Secret**: value that shall be disclosed only to authorized entities.
- **Hash**: cryptographically secure hashing algorithm.
- **Path**: human-readable secret identifier that can used along  with  seed  to
  derive that secret.
- **Symbol set**: set of characters used to decode raw  data  into  the  desired
  encoding format required by a secret.

### Algorithm

Generate randomly a seed `r` with `b` bits of entropy.

Chose a path `p` that can be used to identify a secret.

The path MUST BE a human-readable string and MAY BE arbitrary.

Derive a pseudo-random value `r_s` using `r` and `p`:

$ r_s <- DeriveRawSecret(r, p) $

The value `r_s` is raw data with `b` bits.

Compute the secret:

$ s <- EncodeSecret(r_s, p)$

### Path standard

We propose a standard way to define paths.

A path is a human-readable string with the following format:

```text
<version>/<type>/<scope>/<specifier>
```

Where:

- `version`: the version used in the path standard.
- `type`: the secret type (i.e, plain text password, ssh key, gpg key).
- `scope`: the scope to which the secret applies (i.e, company department).
- `specifier`: precisely specify the secret within the scope (i.e, username)

The scope MAY  represent  an  internet  domain  (i.e,  github.com)  and  secrets
associates with that domain (passwords, ssh  keys),  in  the  case  the  secrets
belong to a single individual.  It  MAY  also  represent  a  subdivision  of  an
organization, in the case  secrets  are  shared  within  a  team.  It  MAY  also
represent both a subdivision and a  domain,  meaning  the  secrets  within  that
domain in that subdivision.

The specifier MAY represent a username or email.  It  MAY  also  represent  more
complex structure adapted to specific needs.

Examples:

```text
v1/ssh/scorpion/webmaster               Default SSH key for user webmaster at host scorpion
v1/ssh/github.com/bar:1                 SSH key 1 for user bar on GitHub
v1/ssh/github.com/bar:2                 SSH key 2 for user bar on GitHub
v1/password/gmail.com/foo               Password for foo@gmail.com
v1/password/hr/careers@company.com      Password for careers email at company.com's Human Resources sector
v1/password/myapp.com/db:root           Password for user root in myapp.com's internal DB.
v1/password/myapp.com/db:app            Password for user app in myapp.com's internal DB.
```

### DeriveRawSecret()

The `DeriveRawSecret` function outputs `b` bits of raw data on inputs  seed  `s`
and path `p`.

One simple, straightforward way to implement it is to use concatenate the inputs
and hash them:

$ r_s <- Hash(s||p) $

This implementation may suit the needs of individuals, which  own  all  password
from their sell password from their seed.

Nonetheless, it does not fit  the  needs  of  complex  organizations  and  teams
because it leaks secrets which should be limited to a scope of an  organization.
For instance, the members of a team needs to know the seed  `s`  to  derive  the
secrets under their control, but that also means they will have  access  to  the
secrets of other teams because they know `s` and the path `p` is not meant to be
secret, but a public identifier of the string.

One approach is for each team to have their single seed shared  among  all  team
members. This also falls into the same problem if the team needs to have  scopes
which are not meant to be accessed by some team members.

Another approach is to require an extra password, which must  be  input  by  the
user, before continue derivation. In this approach, the path `p` uses the symbol
`'` to indicate that at the given scope it should be prompt for a password.

For example, the path `v1/password/hr'/mail:contact` means the  path  should  be
split into `v1/password/hr` and `mail:contact`. The user is  prompted  to  enter
the password, which is read and stored in `pass`.

$ t <- Hash(s||"v1/password/hr"|pass)$

An intermediary output `t` is computed from hashing the  sed  concatenated  with
the first part of the slitted path and the given password. This output  is  then
used as seed for the algorithm again:

$ r_s <- Hash(t||"mail:contact")$

Another advantage of the later approach is that the team members at  HR  do  not
need to known the original secret `s`. They only need  to  known  the  value  of
`Hash(s||"v1/password/hr"|pass)`. Thus, a senior staff can  be  responsible  for
keeping secret `s`  and  `pass`,  and  share  `t`  with  team  members  at  that
subdivision. The team members then use `t` as if it were  their  own  seed  `s`,
that then be used to derive secrets within the team.

Depending on the complexity of the organization, it may have nested  scopes  and
subdivision, which may require nested password managed by  authorized  staff  at
each level.

One may point out that  these  extra  password  steps  contradict  the  original
purpose of the protocol, which aims to derive all secrets from a  single  secret
seed. This is not a contradiction, because the secrets are still derived from  a
single seed and can  be  recorded  from  it.  The  introduction  of  additional,
intermediary passwords just reflects the  complex  nature  of  managing  secrets
within scoped divisions of a large organization. This complexity is intrinsic to
the problem of trust in human organization, and not a protocol  flaw.  Moreover,
the introduction of  additional  password  will  likely  not  be  necessary  for
individuals and small teams.

**Note**: the end user will not know the seed `s` as raw data bits, which should
be handled behind the scenes by an application. If the seed is presented to  the
user for backup purposes, it MUST BE presented to  the  user  in  human-readable
form.

### EncodeSecret()

The raw data generate by `DeriveRawSecret` must be encoded to match the  require
format by the secret. For instance, the bits can be converted to an integer  `k`
representing the secret key of a key pair `(k, kG)` of  a  Elliptic  Curve  with
generator `G`. It could also be used as an input to a hash-to-point function  in
order to ensure some properties of the curve are satisfied. A last  example,  is
to convert the bits into characters to be used  in  a  password.  We  propose  a
method for the later.

One first idea is to split the `b` bits into chunks representing an integer, and
map the integer of each chunk to an  element  of  an  array  of  symbols.  After
encoding the bits into symbols,  the  output  can  be  truncated  to  produce  a
password with the desired length.

However, we must take into account that nowadays  several  systems  have  strict
password requirements: must contain both uppercase and lowercase  letters,  must
have numbers and special characters, must have at least 10  characters, among
others. Thus, it is possible that our pseudo-random password, derived from the
random seed, does match these criteria.

To solve it, we propose defining the following symbol sets:

- lower case english letters: a-z
- upper case english letters: A-Z
- digits: 0-9
- special characters: !"#$%&'()*+,./:;<=>?@[\]^_`{|}~

The user selects which characters MUST BE in the generated  password.  The  user
could select just lower case letters and digits or select all symbol  sets.  The
`b` bits are split into `n` chunks, whose size in bits MAY vary depending on the
total number of elements in the symbol set. Each chunk is mapped  to  a  symbol,
and the output is truncated to match  the  desirable  password  length.  If  the
output password does not fit, we hash the original input again until it fits it.

Here is a pseudo-code for the proposed algorithm:

```text
FUNCTION DerivePassword(s: Seed, path: Path)
    r <- Concatenate(s, path)
    DO
        r <- Hash(r)
        pass <- EncodeSecret(r, path)
    WHILE NOT MatchCriteria(pass)
    RETURN pass
ENDFUNCTION

FUNCTION EncodeSecret(r: RawData, path: Path)
    IF isPasswordTypePath(path)
        symbols <- GetSymbolSet()
        password_length <- GetDesiredPasswordLength()
        chunks <- Split(r)
        pass <- ""
        FOR i FROM 0 TO password_length
            chunk <- chunks[i]
            index <- RandomSetIndex(chunk, symbols)
            pass <- Concatenate(pass, symbols[index])
        ENDFOR
        RETURN pass
    ENDIF
    ...
ENDFUNCTION

FUNCTION RandomSetIndex(chunk: RawData, set: Set)
    integer <- Int(chunk)
    size <- SetSize(set)
    index <- set[integer % size]
    RETURN index
ENDFUNCTION
```

The algorithm will re-hash the digest until the generated password  matches  the
criteria which the user has established, for example, via a  graphical  checkbox
interface or via command line arguments.

The same approach of re-hashing can be used for  the  algorithm  to  generate  a
password whose length is within a range: the user specifies a  range,  which  is
checked inside the `MatchCriteria` function,  and  the  `EncodeSecret`  function
will pick a random password length based on the current value of `r`.  This  can
be useful if the user does not want to  specify  the  password  length  to,  for
example, avoid having all passwords  with  the  same  length,  which  creates  a
fingerprint and can be used to link user accounts, compromising privacy.

## ROADMAP

- [ ] Finish the draft
- [ ] Implement a proof-of-concept program

## LICENSE

MIT.
