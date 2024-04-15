
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule contentis_base64 : Base64
{

    strings:
		$a = /^([A-Za-z0-9+\/\n]{4}){0,}([A-Za-z0-9+\/\n]{2}==|[A-Za-z0-9+\/\n]{3}=)?$/
    condition:
        $a
}
