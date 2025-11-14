"""ASN.1 schema definitions for RPKI Canonical Cache Representation (CCR)."""

from pyasn1.type import univ, namedtype, tag, constraint
from pyasn1.type.useful import GeneralizedTime


# Object Identifier for CCR content type
ID_CT_RPKI_CCR = univ.ObjectIdentifier('1.3.6.1.4.1.41948.828')


class DigestAlgorithmIdentifier(univ.Sequence):
    """Digest algorithm identifier."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )


class Digest(univ.OctetString):
    """Hash digest."""
    pass


class SubjectKeyIdentifier(univ.OctetString):
    """Subject Key Identifier (SKI)."""
    pass


class KeyIdentifier(univ.OctetString):
    """Key Identifier (same as SKI)."""
    pass


class ASID(univ.Integer):
    """Autonomous System Identifier."""
    pass


class AccessDescription(univ.Sequence):
    """Access description for SIA."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', univ.Any())
    )


class SubjectPublicKeyInfo(univ.Sequence):
    """Subject Public Key Info."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.Sequence()),
        namedtype.NamedType('subjectPublicKey', univ.BitString())
    )


# ROA IP Address Family structures
class IPAddress(univ.BitString):
    """IP address as bit string."""
    pass


class IPAddressRange(univ.Sequence):
    """IP address range."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('min', IPAddress()),
        namedtype.NamedType('max', IPAddress())
    )


class IPAddressChoice(univ.Choice):
    """IP address or range choice."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addressPrefix', IPAddress()),
        namedtype.NamedType('addressRange', IPAddressRange())
    )


class IPAddressOrRange(univ.Choice):
    """IP address or range."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addressPrefix', IPAddress()),
        namedtype.NamedType('addressRange', IPAddressRange())
    )


class ROAIPAddress(univ.Sequence):
    """ROA IP address with max length."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('address', IPAddress()),
        namedtype.OptionalNamedType('maxLength', univ.Integer())
    )


class SequenceOfROAIPAddress(univ.SequenceOf):
    """Sequence of ROA IP addresses."""
    componentType = ROAIPAddress()


class ROAIPAddressFamily(univ.Sequence):
    """ROA IP address family (IPv4 or IPv6)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addressFamily', univ.OctetString()),
        namedtype.NamedType('addresses', SequenceOfROAIPAddress())
    )


# CCR-specific structures
class ManifestInstance(univ.Sequence):
    """Manifest instance information."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hash', Digest()),
        namedtype.NamedType('size', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(1000, float('inf'))
        )),
        namedtype.NamedType('aki', KeyIdentifier()),
        namedtype.NamedType('manifestNumber', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, float('inf'))
        )),
        namedtype.NamedType('thisUpdate', GeneralizedTime()),
        namedtype.NamedType('locations', univ.SequenceOf(componentType=AccessDescription()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, float('inf'))
        )),
        namedtype.OptionalNamedType('subordinates', univ.SequenceOf(
            componentType=SubjectKeyIdentifier()
        ).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, float('inf'))))
    )


class ManifestState(univ.Sequence):
    """Manifest state with instances and hash."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mis', univ.SequenceOf(componentType=ManifestInstance())),
        namedtype.NamedType('mostRecentUpdate', GeneralizedTime()),
        namedtype.NamedType('hash', Digest())
    )


class ROAPayloadSet(univ.Sequence):
    """ROA payload set with AS and IP blocks."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('asID', ASID()),
        namedtype.NamedType('ipAddrBlocks', univ.SequenceOf(
            componentType=ROAIPAddressFamily()
        ).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, 2)))
    )


class ROAPayloadState(univ.Sequence):
    """ROA payload state."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rps', univ.SequenceOf(componentType=ROAPayloadSet())),
        namedtype.NamedType('hash', Digest())
    )


class ASPAPayloadSet(univ.Sequence):
    """ASPA payload set."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('customerASID', ASID()),
        namedtype.NamedType('providers', univ.SequenceOf(componentType=ASID()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, float('inf'))
        ))
    )


class ASPAPayloadState(univ.Sequence):
    """ASPA payload state."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('aps', univ.SequenceOf(componentType=ASPAPayloadSet())),
        namedtype.NamedType('hash', Digest())
    )


class TrustAnchorState(univ.Sequence):
    """Trust anchor state."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('skis', univ.SequenceOf(
            componentType=SubjectKeyIdentifier()
        ).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, float('inf')))),
        namedtype.NamedType('hash', Digest())
    )


class RouterKey(univ.Sequence):
    """Router key with SKI and SPKI."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ski', SubjectKeyIdentifier()),
        namedtype.NamedType('spki', SubjectPublicKeyInfo())
    )


class RouterKeySet(univ.Sequence):
    """Router key set for an AS."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('asID', ASID()),
        namedtype.NamedType('routerKeys', univ.SequenceOf(componentType=RouterKey()).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, float('inf'))
        ))
    )


class RouterKeyState(univ.Sequence):
    """Router key state."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rksets', univ.SequenceOf(componentType=RouterKeySet())),
        namedtype.NamedType('hash', Digest())
    )


class RpkiCanonicalCacheRepresentation(univ.Sequence):
    """Main CCR structure - using EXPLICIT TAGS."""
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )),
        namedtype.NamedType('hashAlg', univ.ObjectIdentifier()),  # Simplified to just OID
        namedtype.NamedType('producedAt', GeneralizedTime()),
        namedtype.OptionalNamedType('mfts', ManifestState().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )),
        namedtype.OptionalNamedType('vrps', ROAPayloadState().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        )),
        namedtype.OptionalNamedType('vaps', ASPAPayloadState().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        )),
        namedtype.OptionalNamedType('tas', TrustAnchorState().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
        )),
        namedtype.OptionalNamedType('rks', RouterKeyState().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5)
        ))
    )


class EncapsulatedContentInfo(univ.Sequence):
    """CMS Encapsulated Content Info."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('eContentType', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('eContent', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        ))
    )
