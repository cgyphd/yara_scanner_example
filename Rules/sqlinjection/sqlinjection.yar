rule findSql
{
	strings:
		$char1="1=1"
		$char2="--"
		$char3="#"
		$str1="CONCAT" nocase
		$str2="CHAR" nocase
		$str3="Hex" nocase
		$str4="admin'--"
		$str5="admin'#"
		$str6="admin'/*"
		$str7="anotheruser" nocase
		$str8="doesntmatter" nocase
		$str9="MD5" nocase
		$str10="HAVING" nocase
		$str11="ORDERBY" nocase
		$str12="CAST" nocase
		$str13="CONVERT" nocase
		$str14="insert" nocase
		$str15="@@version"
		$str16="bcp" nocase
		$str17="VERSION" nocase
		$str18="WHERE" nocase
		$str19="LIMIT" nocase
		$str20="EXEC" nocase
		$str21="';shutdown--"
		$str22="WAITFORDELAY"  nocase
		$str23="NOTEXIST"  nocase
		$str24="NOTIN"  nocase
		$str25="BENCHMARK" nocase
		$str26="pg_sleep"
		$str27="sleep"
		$str28="--sp_password" nocase
		$str29="SHA1" nocase
		$str30="PASSWORD" nocase
		$str31="ENCODE" nocase
		$str32="COMPRESS" nocase
		$str33="SCHEME" nocase
		$str34="ROW_COUNT" nocase
		$str35="DROPmembers--" nocase
		$str36="ASCII" nocase
		$str37="UNION" nocase
		$str38="UNIONSELECT" nocase
		$str39="INFORMATION" nocase
		$str40="SCHEMA" nocase
		$str41="INFORMATION_SCHEMA" nocase
	condition:
		any of them
}