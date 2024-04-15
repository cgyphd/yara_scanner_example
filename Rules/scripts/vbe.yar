rule Contains_VBE_File2
{
	strings:
		$vbe = /#@~\^.+\^#~@/
	condition:
		$vbe 

}

