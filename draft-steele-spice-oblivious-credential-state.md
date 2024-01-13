---
title: "Oblivious Credential State"
category: info

docname: draft-steele-spice-oblivious-credential-state-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Secure Patterns for Internet CrEdentials"
keyword:
 - credential status
 - privacy preserving
 - oblivious
venue:
  group: "Secure Patterns for Internet CrEdentials"
  type: "Working Group"
  mail: "spice@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spice/"
  github: "OR13/draft-steele-spice-oblivious-credential-state"
  latest: "https://OR13.github.io/draft-steele-spice-oblivious-credential-state/draft-steele-spice-oblivious-credential-state.html"

author:
 -
    fullname: "Orie Steele"
    organization: Transmute
    email: "orie@transmute.industries"

normative:
  RFC4122: UUID
  RFC6570: URI-Template
  RFC9458: OHTTP
  WHATWG.URL:
    title: "URL - Living Standard"
    target: https://url.spec.whatwg.org/

informative:
  RFC7519: JWT
  RFC8932:
  RFC2560: OCSP
  RFC5755: ATTR-CERT
  I-D.draft-mcmillion-keytrans-architecture: KT-ARCH
  I-D.draft-ietf-oauth-status-list: OAUTH-STATUS-LIST
  ZKA:
    title: "Zero-Knowledge Accumulators and Set Operations"
    target: https://eprint.iacr.org/2015/404.pdf
  W3C.VC-BITSTRING-STATUS-LIST:
    title: "Bitstring Status List v1.0"
    target: https://www.w3.org/TR/vc-bitstring-status-list/



--- abstract

Issuers of Digital Credentials enable dynamic state or status checks through the use of dereferenceable identifiers, that resolve to resources providing herd privacy.
Privacy in such systems is determined not just from the size of the herd, and the cryptographic structure encoding it, but also from the observability of access to shared state.
This document describes a privacy preserving state management system for digital credentials based on Oblivious HTTP that addresses both data model and protocol risks associated with digital credentials with dynamic state.

--- middle

# Introduction

Digitial Credentials often have a validity period, which indicates the time at which the claims become active for the subject according to the issuer, and the time at which the issuer specifies the claims are no longer to be considered asserted by the issuer.

A typical example is a digital drivers license, which has an activation date, and an expiration date.

When the activation date is in the past, and the expiration date is in the future, we consider the license to be valid at the current time.

A verifier might wonder if such licenses are suspended or revoked, even if the validity period is acceptable.

A common solution is to the issuer of the credential to provide a resource that reflects information about the state of the credential over time.

Because issuer's track the presentation of digital credentials if a verifier where to ask the issuer about the state of a specific digital credential, it common to see credential states be merged into blocks, or herds, where an issuer can deliver the block to the verifier upon request, without learning which specific digital credential the verifier is interested in.

Unfortunatly, the metadata associated with resolving credential state can leak time and location information about the presentation of credentials over time.

This document addresses this risk by introducing a mediator which is trusted by the verifier.

# Credential State

To simplify interpretation of resolution of credential state resources, this document uses the following aliases for the terms defined in {{-OHTTP}}.

The `Verifier's Software` is the `Oblivious HTTP Client`.

The `Mediator's Credential State Resource` is the `Oblivious Relay Resource`.

The `Issuer's Gateway Resource` is the `Gateway Resource`.

The `Issuer's Credential State Resource` is the `Target Resource`.

The critical privacy property is obtained by the verifier's client relying on the `Mediator's Credential State Resource` instead of `Issuer's Credential State Resource`.

In order to achieve this property, while preserving the property that issuer's do not know which verifier's will be interested in dynamic state information associated with their credentials, the issuer includes the identifier for their `Issuer's Credential State Resource` in their credential claim sets, however the verifier rewrites this URL to be their `Mediator's Credential State Resource` before resolution.

Editor note: is there a simpler solution here?

~~~aasvg
 .--------.         +----------+         .-------.
| Verifier +<------>+ Mediator +<------>+ Issuer  |
 '--------'         +----------+         '-------'
~~~

## Identifier

While many different protocol schemes can be used to identify resources, to improve interoperability and reduce attack surface, this document requires credential state resources to be identified with https URLS, as described in {{WHATWG.URL}}.

The following URI Templates, as described in {{-URI-Template}} are required to improve interoperability and reduce the chances of degrading the privacy properties through the inclusion of extraneos information in the identifiers embedded in credentials.

- `issuer` MUST support internationalizaton considerations, as described in {{WHATWG.URL}}, for example: `🏛️.example`

- `mediator` MUST support internationalizaton considerations, as described in {{WHATWG.URL}}, for example: `🚛.example`

- `resource-name` MUST be a URN as described in {{-UUID}}, for example: `urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6`

### Issuer's Credential State Resource

~~~
https://{issuer}\
/credential-states/{resource-name}
~~~

~~~
https://🏛️.example\
/credential-states/urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
~~~
{: #example-issuer-credential-state-resource-urls align="left" title="Issuer Credential State Resources"}

### Mediator's Credential State Resource

~~~
https://{issuer}.{mediator}\
/credential-states/{resource-name}
~~~

~~~
https://🏛️.example.🚛.example\
/credential-states/urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
~~~
{: #example-mediator-credential-state-resource-urls align="left" title="Mediator Credential State Resources"}

## Resources

Credential state resources typically rely on a similar content type as the credentials that require them.

Mixing different content types for credentials and their state, increases implementation costs and harms interoperability.

The credential state resource MUST be secured with the same content type that was used to secure the digital credential that has dynamic state.

For example, a JSON Web Token, {{-JWT}} based digital credential must rely on a {{-JWT}} based credential state resource.

There are many different content types that can be used to secure digital credentials, this document does not require a specific content type to be used.

The `Accept` header MUST be supported, and the `application/cose` content type SHOULD be supported.

## Processing Credential State Resources

Validation of the digital credential state MUST occur after verification.

Validation of the digital credential validity period MUST occur before credential state checks.

Implementers are cautioned that concepts like "suspended" or "revoked" are interpretted differently and used differently by issuers.

All dynamic claims provided through credential state resources MUST be considered issuer defined, and cannot be interpretted globally.

Interpretting the structure of the `Issuer's Credential State Resource` is outside the scope of this document.

However, other documents describe this process in detail.

{{W3C.VC-BITSTRING-STATUS-LIST}} provides guidance on processing resources that secure the content type `application/vc+ld+json`, such as `application/cose`.

{{-OAUTH-STATUS-LIST}} provides guidance on processing resources of the content type `application/cwt`, and `application/jwt`.

## Techniques

### CRL Distribution Points

{{-ATTR-CERT}} described a mechanism for verifiers to check the revocation status of attribute certificates.

### Online Certificate Status Protocol

{{-OCSP}} described a protocol useful in determining the current status of a digital certificate without requiring CRLs.

### Bitmaps

In this approach, the size of the herd is the length of the bitmap, and the state of a digital credential claim is the value of the bit at a given index.

Scaling this approach can be difficult, as a seperate list is needed for each dynamic claim in a digital credential.

This scalling challenge can be partially addressed by consuming multiple bits at a given index, however, the resulting enumeration needs to be consistently understood.

A common solution to consistent interpretation of enumerations is the establishment of a registry, however this can become impractical depending on the nature of the issuer's need to express dynamic state.

Publishing a dictionary per issuer, or per sets of issuer's can help address these challenges for some use cases.

### Cryptographic Accumulators

{{ZKA}} describes an approach to expressing proofs of set membership.

### Bloom Filters

{{Section B.2.7 of RFC8932}} mentions an application of bloom filters, that can be applied to communicating credential state assuming the probabilistic nature of bloom filters is acceptable to the verifier.

### Transparency Services

Tree structures, such as described in {{-KT-ARCH}} can be used to provide advanced membership proofs, such as proving inclusion, consistency, non inclusion, and freshness.

# Terminology

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
