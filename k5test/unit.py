import os
import unittest

from k5test import _utils, realm


# test case class
class KerberosTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.realm = realm.K5Realm()

    @classmethod
    def tearDownClass(cls):
        cls.realm.stop()
        del cls.realm


# decorators
def gssapi_extension_test(extension_name, extension_text):
    def make_ext_test(func):
        def ext_test(self, *args, **kwargs):
            if _utils.import_gssapi_extension(extension_name) is None:
                self.skipTest(
                    "The %s GSSAPI extension is not supported by "
                    "your GSSAPI implementation" % extension_text
                )
            else:
                func(self, *args, **kwargs)

        return ext_test

    return make_ext_test


_KRB_VERSION = None


def krb_minversion_test(target_version, problem, provider=None):
    global _KRB_VERSION
    if _KRB_VERSION is None:
        _KRB_VERSION = _utils.get_output("krb5-config --version")
        _KRB_VERSION = _KRB_VERSION.split(" ")[-1].split(".")

    def make_ext_test(func):
        def ext_test(self, *args, **kwargs):
            if _KRB_VERSION < target_version.split(".") and (
                not provider or self.realm.lower() == provider.lower()
            ):
                self.skipTest(
                    "Your GSSAPI (version %s) is known to have "
                    "problems with %s" % (_KRB_VERSION, problem)
                )
            else:
                func(self, *args, **kwargs)

        return ext_test

    return make_ext_test


def krb_plugin_test(plugin_type, plugin_name):
    # TODO(directxman12): add a way to make this look for
    # platform-specific library extensions
    krb5_plugin_path = _utils.find_plugin_dir()
    plugin_path = None
    if krb5_plugin_path:
        plugin_path = os.path.join(krb5_plugin_path, plugin_type, f"{plugin_name}.so")

    def make_krb_plugin_test(func):
        def krb_plugin_test(self, *args, **kwargs):
            if not plugin_path or not os.path.exists(plugin_path):
                self.skipTest(
                    "You do not have the GSSAPI {type}"
                    "plugin {name} installed".format(type=plugin_type, name=plugin_name)
                )
            else:
                func(self, *args, **kwargs)

        return krb_plugin_test

    return make_krb_plugin_test


def krb_provider_test(providers, problem):
    def make_krb_provider_test(func):
        def krb_provider_test(self, *args, **kwargs):
            provider_list = [p.lower() for p in providers]
            if self.realm.provider.lower() not in provider_list:
                self.skipTest(
                    f"Your GSSAPI (provider {self.realm.provider}) "
                    f"is known to have problems with {problem}"
                )
            else:
                func(self, *args, **kwargs)

        return krb_provider_test

    return make_krb_provider_test
