from itertools import product
import logging
import re
import unicodedata


LOG = logging.getLogger(__file__)

INSTANCE_REGEX_PATTERN = re.compile(b'^.*[^' + b''.join(chr(c).encode('utf-8') for c in range(0x00, 0x1F)) + chr(0x7F).encode('utf-8') + b'].*$')
SERVICE_NAME_REGEX_PATTERN = re.compile(b'^([0-9]+(\-){0,1})*[A-Za-z]((\-){0,1}[A-Za-z0-9])*$')


class Error(Exception):
    pass


class InvalidInstanceError(Error):
    pass


class InvalidServiceError(Error):
    pass


def instance_to_bytes(instance, escape=True):
    """
    Encode unicode string into bytes by taking into account all restrictions set on the <Instance> portion.

    @param instance: The <Instance> portion of a Service Instance Name.
    @type instance: unicode

    @param escape: Escape all dots and backslashes by prepending backslash to each char.
    Note that escaping may increase length of the string and otherwise good string may exceed 63 octets limitation.
    @type escape: bool

    @return: Bytes that represent the <Instance> portion.
    @rtype: bytes

    @see: RFC 6763, sections 4.1.1. and 4.3.
    """
    instance = unicodedata.normalize('NFC', instance).encode('utf-8')

    if not re.match(INSTANCE_REGEX_PATTERN, instance):
        raise InvalidInstanceError("instance MUST follow rules defined in RFC 6763, 4.1.1.")

    if escape:
        instance = instance.replace(b'\\', b'\\\\')
        instance = instance.replace(b'.', b'\\.')

    if len(instance) > 63:
        raise InvalidInstanceError("as per RFC 6763 DNS labels are currently limited to 63 octets in length")

    return instance


def service_to_bytes(service):
    """
    Encode unicode string into bytes by taking into account all restrictions set on the <Service> portion.

    <Service> MUST look like this: _<Name>._tcp or _<service name>._udp

    Where <Name>, quoting RFC 6763, "may be no more than fifteen characters
    long (not counting the mandatory underscore), consisting of only letters, digits, and hyphens,
    must begin and end with a letter or digit, must not contain consecutive hyphens,
    and must contain at least one letter."

    @param service: The <Service> portion of a Service Instance Name.
    @type service: unicode

    @return: Bytes that represent the <Service> portion.
    @rtype: bytes

    @see: RFC 6335, 5.1.
    @see: RFC 6763, 4.1.2. and 4.7.
    """
    service = service.encode('ascii')
    name, sep, proto = service.rpartition(b'.')

    if not name:
        raise InvalidServiceError("as per RFC 6763 service MUST consist of 2 labels: service name and protocol")

    if proto != b'_tcp' and proto != b'_udp':
        raise InvalidServiceError("as per RFC 6763, second label of the service MUST be either '_tcp' or '_udp'")

    if not name.startswith(b'_'):
        raise InvalidServiceError("as per RFC 6763, service name MUST start with and underscore '_'")

    name = name[1:]

    if not 0 < len(name) < 16:
        raise InvalidServiceError("as per RFC 6335, service name MUST be at least 1 character and no more than 15 characters long (not counting the mandatory underscore)")

    if not re.match(SERVICE_NAME_REGEX_PATTERN, name):
        raise InvalidServiceError("service name MUST follow rules defined in RFC 6335, 5.1.")

    return service


def domain_to_bytes(domain):
    """
    Encode unicode string into bytes by taking into account all restrictions set on the <Domain> portion and
    recommendations to partially convert domain into punycode.

    @param domain: The <Domain> portion of a Service Instance Name.

    @return: List of all variations of the domain from completely UTF-8 encoded to completely Punycode encoded string.
    First item is always completely UTF-8 encoded string, second item is UTF-8 encoded string with last (root) label
    Punycode encoded and so on until every label in domain is Punycode encoded.
    @rtype: list

    @see: RFC 6763, 4.1.3.
    """
    domain = unicodedata.normalize('NFC', domain)
    labels = domain.split('.')
    idna_labels = [l.encode('idna') for l in labels]
    options = []

    for i in product(*zip(labels, idna_labels)):
        if len(options) and options[-1] != i:
            options.append(i)

    return options


class Service(object):
    def __init__(self, instance, service, domain):
        """

        @param instance: E.g. b'Service\032Discovery'
        @param service: E.g. b'_http._tcp'
        @param domain: E.g. b'Building 2, 4th Floor.example.com.'

        @see Service.instance_to_bytes
        @see Service.service_to_bytes
        @see Service.domain_to_bytes
        """
        self._instance = instance
        self._service = service
        self._domain = domain

    @property
    def instance(self):
        return self._instance

    @property
    def service(self):
        return self._service

    @property
    def domain(self):
        return self._domain

    @property
    def service_instance_name(self):
        return b'.'.join([self.instance, self.service, self.domain])
