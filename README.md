K5Test
======

*k5test* is a library for setting up self-contained Kerberos 5 environments,
and running Python unit tests inside those environments.  It is based on
the file of the same name found alongside the MIT Kerberos 5 unit tests.

Using k5test to set up a Kerberos 5 deployment
----------------------------------------------

*k5test* can be used to set up a self-contained MIT krb5 or Heimdal
environment.  This is useful for testing applications without having to
manipulate existing Kerberos realms, or having to set up a full Kerberos
deployment by hand.

To set up a realm, use the `k5test.K5Realm` class.  The constructor accepts
several useful arguments for controlling which parts get set up; refer to the
inline documentation for more information.

Using k5test to run unit tests
------------------------------

Instead of having test cases inherit from `unittest.TestCase`, inherit from
`k5test.KerberosTestCase`, which will automatically set up a Kerberos 5
environment, before the test case, and tear it down afterwards.

Additionally, several decorators are defined.  the
`k5test.gssapi_extension_test(extension_name, human_readable_name)` decorator
(which requires `python-gssapi`) allows you to skip tests with installations
that don't support a particular GSSAPI extension.  The the
`k5test.krb_minversion_test(target_version, problem_name)` decorator allows
you to skip tests when running a version of krb5 less that the required
version.  The `k5test.krb_plugin_test(plugin_type, plugin_name)` decorator
allows you to skip tests for installations that don't have a particular plugin
installed.
