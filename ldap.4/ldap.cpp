// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

//##define LDAP_UNICODE 0
//----------------------------------------------
// Performing an LDAP Synchronous Search.
//
// Be aware that you must set the command prompt screen buffer 
// height to 350 and the width to 90.
//-------------------------------------------------------------

#include "stdafx.h"
#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <rpc.h>
#include <rpcdce.h>
#include <stdio.h>
#include <stdlib.h>
#include <sql.h>
#include <sqlext.h>
#include <ctime>
#include <string>

void GetConnected(char* samaccountname, char* givenname, char* sn,char* middlename, char* Displayname, char* Mail, char* Department, char* physicalDeliveryOfficeName, char* Title, char* streetAddress, char* l, char* st, char* telephoneNumber, char* pextensionAttribute1, char* SERVER , char* UID, char* PWD, char* DATABASE);

//-----------------------------------------------------------
// This subroutine must have validated credentials (name and
// password) passed to it.
//-----------------------------------------------------------
int MyLDAPSearch(PCHAR pUserName, PCHAR pPassword,PCHAR pHostname, PCHAR DNString, PCHAR filterString,char* SERVER , char* UID, char* PWD, char* DATABASE)
{
    //---------------------------------------------------------
    // Initialize a session. LDAP_PORT is the default port, 389.
    //---------------------------------------------------------
    //PCHAR hostName = "fabrikam.com";
	//PCHAR hostName = "10.66.101.82";
	PCHAR hostName = pHostname;
    LDAP* pLdapConnection = NULL;
    
    pLdapConnection = ldap_init(hostName, LDAP_PORT);
	//pLdapConnection = ldap_sslinit(hostName, LDAP_SSL_PORT, 1);
    
    if (pLdapConnection == NULL)
    {
        printf("ldap_init failed with 0x%x.\n",LdapGetLastError());
        ldap_unbind(pLdapConnection);
        return -1;
    }
    else
        printf("ldap_init succeeded \n");
    
    
    //-------------------------------------------------------
    // Set session options.
    //-------------------------------------------------------
    ULONG version = LDAP_VERSION3;
    //ULONG numReturns = 10;
	ULONG numReturns = 10;
	//ULONG numReturns = 1000;
	//ULONG numReturns = 100000;
    ULONG lRtn = 0;
    

    // Set the version to 3.0 (default is 2.0).
    lRtn = ldap_set_option(
                    pLdapConnection,           // Session handle
                    LDAP_OPT_PROTOCOL_VERSION, // Option
                    (void*) &version);         // Option value

    if(lRtn == LDAP_SUCCESS)
        printf("ldap version set to 3.0 \n");
    else
    {
        printf("SetOption Error:%0lX\n", lRtn);
        ldap_unbind(pLdapConnection);
        return -1;
    }

    // Set the limit on the number of entries returned to 10.
    lRtn = ldap_set_option(
                    pLdapConnection,       // Session handle
                    LDAP_OPT_SIZELIMIT,    // Option
                    (void*) &numReturns);  // Option value

    if(lRtn == LDAP_SUCCESS)
        printf("Max return entries set to 10 \n");
    else
    {
        printf("SetOption Error:%0lX\n", lRtn);
        ldap_unbind(pLdapConnection);
        return -1;
    }
	
	//  Verify that SSL is enabled on the connection.
	//  (returns LDAP_OPT_ON/_OFF).
#if 0
	LONG lv = 0;
	INT returnCode = 0;
	printf("Checking if SSL is enabled\n");
	returnCode = ldap_get_option(pLdapConnection, LDAP_OPT_SSL, (void*)&lv);
	if (returnCode != LDAP_SUCCESS)
		goto FatalExit;

	//  If SSL is not enabled, enable it.
	if ((void*)lv == LDAP_OPT_ON)
		printf("SSL is enabled\n");
	else
	{
		printf("SSL not enabled.\n SSL being enabled...\n");
		returnCode = ldap_set_option(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
		if (returnCode != LDAP_SUCCESS)
			goto FatalExit;
	}
#endif 
    
    
    //--------------------------------------------------------
    // Connect to the server.
    //--------------------------------------------------------
    
    lRtn = ldap_connect(pLdapConnection, NULL);
    
    if(lRtn == LDAP_SUCCESS)
        printf("ldap_connect succeeded \n");
    else
    {
        printf("ldap_connect failed with 0x%lx.\n",lRtn);
        ldap_unbind(pLdapConnection);
        return -1;
    }
    
    
    //--------------------------------------------------------
    // Bind with credentials.
    //--------------------------------------------------------
	//PCHAR pMyDN = "DC=ohioplugin8,DC=net";
	//PCHAR pMyDN = "OU=MyTestOU,DC=ohioplugin8,DC=net";
	PCHAR pMyDN = DNString;
	//PCHAR pMyDN = "DC=ohioadplugin,DC=net";
    SEC_WINNT_AUTH_IDENTITY secIdent;
 
    secIdent.User = (unsigned char*)pUserName;
	//secIdent.User = (unsigned short*)pUserName;
    secIdent.UserLength = strlen(pUserName);
    secIdent.Password = (unsigned char*)pPassword;
	//secIdent.Password = (unsigned short*)pPassword;
    secIdent.PasswordLength = strlen(pPassword);
    secIdent.Domain = (unsigned char*)hostName;
	//secIdent.Domain = (unsigned short*)hostName;
    secIdent.DomainLength = strlen(hostName);
    secIdent.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    
	lRtn = ldap_bind_s(
		pLdapConnection,      // Session Handle
		pMyDN,                // Domain DN
		(PCHAR)&secIdent,     // Credential structure
		//LDAP_AUTH_SIMPLE);
		LDAP_AUTH_NEGOTIATE); // Auth mode
		//LDAP_AUTH_SIMPLE);
    if(lRtn == LDAP_SUCCESS)
    {
        printf("ldap_bind_s succeeded \n");
        secIdent.Password = NULL; // Remove password pointer
        pPassword = NULL;         // Remove password pointer
    }
    else
    {
        printf("ldap_bind_s failed with 0x%lx.\n",lRtn);
        ldap_unbind(pLdapConnection);
        return -1;
    }


#if 0
	//PWCHAR user_name = L"adm@ad.domain.name";
	//PWCHAR password = L"mypassword";

	PCHAR user_name = "administrator@WIN-VKI3OAPV1BL.ohioplugin8.net";
	//PCHAR user_name = "administrator";
	PCHAR password = "87UxmymR.q";

	lRtn = ldap_simple_bind_s(pLdapConnection, user_name, password);
	if (lRtn == LDAP_SUCCESS)
	{
		printf("ldap_simple_bind_s succeeded \n");
	}
	else
	{
		printf("ldap_simple_bind_s failed with 0x%lx.\n", lRtn);
		ldap_unbind(pLdapConnection);
		return -1;
	}

#endif 


	/* FOR PAGING */
	char		 *server, *base, *filter, *scopes[] = { "BASE", "ONELEVEL", "SUBTREE" };
	int		 scope;
	LDAP		 *ld;
	int		   l_rc, l_entries, l_port, l_entry_count = 0, morePages, l_errcode = 0, page_nbr;
	//unsigned long  pageSize;
	//unsigned long  pageSize = 100000;
	//unsigned long  pageSize = 100000;
	unsigned long  pageSize = 3000;
	struct berval  *cookie = NULL;
	char           pagingCriticality = 'T', *l_dn;
	//char           pagingCriticality = 'F', *l_dn;
	unsigned long  totalCount;
	LDAPControl    *pageControl = NULL, *M_controls[2] = { NULL, NULL }, **returnedControls = NULL;
	LDAPMessage	   *l_result, *l_entry;

	/******************************************************************/
	/* Get one page of the returned results each time                 */
	/* through the loop                                               */
	do
	{
		LDAPMessage* pSearchResult;
		l_rc = ldap_create_page_control(pLdapConnection, pageSize, cookie, pagingCriticality, &pageControl);

		/* Insert the control into a list to be passed to the search.     */
		M_controls[0] = pageControl;

		/* Search for entries in the directory using the parmeters.       */
		//filter = "(&(objectCategory=person)(objectClass=user))";
		//filter = "(objectClass=*)";
		//filter = "(objectClass=user)";
		filter = filterString;
		//filter = "(objectCategory=organizationalUnit)";
		scope = LDAP_SCOPE_SUBTREE;
		base = pMyDN;
		//l_rc = ldap_search_ext_s(pLdapConnection, base, scope, filter, NULL, 0, M_controls, NULL, NULL, 0, &l_result);
		//l_rc = ldap_search_ext_s(pLdapConnection, base, scope, filter, NULL, 0, M_controls, NULL, NULL, 0, &pSearchResult);
		l_rc = ldap_search_ext_s(pLdapConnection, base, scope, filter, NULL, 0, M_controls, NULL, NULL, 0, &pSearchResult);

		if ((l_rc != LDAP_SUCCESS) & (l_rc != LDAP_PARTIAL_RESULTS))
		{
			printf("==Error==");
			printf("  Failure during a search.  Return code is %d.\n", l_rc);
			ldap_unbind(pLdapConnection);
			break;
		}

		/* Parse the results to retrieve the contols being returned.      */
		//l_rc = ldap_parse_result(ld, l_result, &l_errcode, NULL, NULL, NULL, &returnedControls, LDAP_FALSE);
		//l_rc = ldap_parse_result(ld, l_result, (ULONG*)&l_errcode, NULL, NULL, NULL, &returnedControls, LDAP_FALSE);
		//l_rc = ldap_parse_result(pLdapConnection, l_result, (ULONG*)&l_errcode, NULL, NULL, NULL, &returnedControls, FALSE);
		l_rc = ldap_parse_result(pLdapConnection, pSearchResult, (ULONG*)&l_errcode, NULL, NULL, NULL, &returnedControls, FALSE);
		

		if (cookie != NULL)
		{
			ber_bvfree(cookie);
			cookie = NULL;
		}

		/* Parse the page control returned to get the cookie and          */
		/* determine whether there are more pages.                        */
		l_rc = ldap_parse_page_control(pLdapConnection, returnedControls, &totalCount, &cookie);

		/* Determine if the cookie is not empty, indicating there are more pages for these search parameters. */
		if (cookie && cookie->bv_val != NULL && (strlen(cookie->bv_val) > 0))
		{
			//morePages = LDAP_TRUE;
			morePages = TRUE;
		}
		else
		{
			//morePages = LDAP_FALSE;
			morePages = FALSE;
		}

		/* Cleanup the controls used. */
		if (returnedControls != NULL)
		{
			ldap_controls_free(returnedControls);
			returnedControls = NULL;
		}
		M_controls[0] = NULL;
		ldap_control_free(pageControl);
		pageControl = NULL;

		/* FOR PAGING */

	//----------------------------------------------------------
	// Perform a synchronous search of fabrikam.com for 
	// all user objects that have a "person" category.
	//----------------------------------------------------------
		ULONG errorCode = LDAP_SUCCESS;
		//LDAPMessage* pSearchResult;
		//PCHAR pMyFilter = "(&(objectCategory=person)(objectClass=user))";
		//PCHAR pMyFilter = "(objectClass=*)";
		//PCHAR pMyFilter = "(objectClass=*)";
		PCHAR pMyFilter = "(objectClass=user)";
		//PCHAR pMyFilter = "(objectCategory=organizationalUnit)";

		//----------------------------------------------------------
		// Get the number of entries returned.
		//----------------------------------------------------------
		ULONG numberOfEntries;

		numberOfEntries = ldap_count_entries(
			pLdapConnection,    // Session handle
			pSearchResult);     // Search result

		if (numberOfEntries == NULL)
		{
			printf("ldap_count_entries failed with 0x%0lx \n", errorCode);
			ldap_unbind_s(pLdapConnection);
			if (pSearchResult != NULL)
				ldap_msgfree(pSearchResult);
			return -1;
		}
		else
			printf("ldap_count_entries succeeded \n");

		printf("The number of entries is: %d \n", numberOfEntries);


		//----------------------------------------------------------
		// Loop through the search entries, get, and output the
		// requested list of attributes and values.
		//----------------------------------------------------------
		LDAPMessage* pEntry = NULL;
		PCHAR pEntryDN = NULL;
		ULONG iCnt = 0;
		char* sMsg;
		BerElement* pBer = NULL;
		PCHAR pAttribute = NULL;
		PCHAR* ppValue = NULL;
		ULONG iValue = 0;

		for (iCnt = 0; iCnt < numberOfEntries; iCnt++)
		{
			// Get the first/next entry.
			if (!iCnt)
				pEntry = ldap_first_entry(pLdapConnection, pSearchResult);
			else
				pEntry = ldap_next_entry(pLdapConnection, pEntry);

			// Output a status message.
			sMsg = (!iCnt ? "ldap_first_entry" : "ldap_next_entry");
			if (pEntry == NULL)
			{
				printf("%s failed with 0x%0lx \n", sMsg, LdapGetLastError());
				ldap_unbind_s(pLdapConnection);
				ldap_msgfree(pSearchResult);
				return -1;
			}
			else
				//printf("%s succeeded\n", sMsg);

			// Output the entry number.
			printf("ENTRY NUMBER %i \n", iCnt);
			//fprintf(fp, "ENTRY NUMBER %i \n", iCnt);

			// Get the first attribute name.
			pAttribute = ldap_first_attribute(
				pLdapConnection,   // Session handle
				pEntry,            // Current entry
				&pBer);            // [out] Current BerElement

			/*To Store and Send to DB for Insert Query*/
			char psAMAccountName[255];
			memset(psAMAccountName,'\0',255);
			char pgivenName[255];
			memset(pgivenName,'\0',255);
			char psn[255];
			memset(psn,'\0',255);
			char pinitials[255];
			memset(pinitials,'\0',255);
			char pdisplayName[255];
			memset(pdisplayName,'\0',255);
			//char* pmail = NULL; //mail is the last attribute hence not needed
			char pdepartment[255];
			memset(pdepartment,'\0',255);
			char pphysicalDeliveryOfficeName[255];
			memset(pphysicalDeliveryOfficeName,'\0',255);
			char ptitle[255];
			memset(ptitle,'\0',255);
			char pstreetAddress[255];
			memset(pstreetAddress,'\0',255);
			char pextensionAttribute1[255];
			memset(pextensionAttribute1,'\0',255);
			char pl[255];
			memset(pl,'\0',255);
			char pst[255];
			memset(pst,'\0',255);
			char ptelephoneNumber[255];
			memset(ptelephoneNumber,'\0',255);
			char pmail[255];
			memset(pmail,'\0',255);



  // Output the attribute names for the current object
  // and output values.
			while (pAttribute != NULL)
			{
				if(!strcmp(pAttribute, "sAMAccountName") ||
				!strcmp(pAttribute, "givenName") ||
				!strcmp(pAttribute, "sn") ||
				!strcmp(pAttribute, "initials") ||
				!strcmp(pAttribute, "displayName") ||
				!strcmp(pAttribute, "mail") ||
				!strcmp(pAttribute, "title") ||
				!strcmp(pAttribute, "department") ||
				!strcmp(pAttribute, "physicalDeliveryOfficeName") ||
				!strcmp(pAttribute, "telephoneNumber")	||	
				!strcmp(pAttribute, "l") ||
				!strcmp(pAttribute, "st")	||		
				!strcmp(pAttribute, "extensionAttribute1")	||		
				//!strcmp(pAttribute, "Agency Code")	||		
				!strcmp(pAttribute, "streetAddress")) 
				{

					// Output the attribute name.
					printf("     ATTR: %s", pAttribute);
					//fprintf(fp, "     ATTR: %s\n", pAttribute);

					
					// Get the string values.

					ppValue = ldap_get_values(
						pLdapConnection,  // Session Handle
						pEntry,           // Current entry
						pAttribute);      // Current attribute

		// Print status if no values are returned (NULL ptr)
					if (ppValue == NULL)
					{
						printf(": [NO ATTRIBUTE VALUE RETURNED]");
					}

					// Output the attribute values
					else
					{
						iValue = ldap_count_values(ppValue);
						if (!iValue)
						{
							printf(": [BAD VALUE LIST]");
						}
						else
						{
#if 1
							if(!strcmp(pAttribute, "sAMAccountName"))
							{
								strcpy(psAMAccountName,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(psAMAccountName,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "givenName"))
							{
								strcpy(pgivenName,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pgivenName,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "sn"))
							{
								strcpy(psn,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(psn,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "initials"))
							{
								strcpy(pinitials,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pinitials,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "displayName"))
							{
								strcpy(pdisplayName,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pdisplayName,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "department"))
							{
								strcpy(pdepartment,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pdepartment,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "physicalDeliveryOfficeName"))
							{
								strcpy(pphysicalDeliveryOfficeName,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pphysicalDeliveryOfficeName,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "title"))
							{
								strcpy(ptitle,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(ptitle,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "extensionAttribute1"))
							{
								strcpy(pextensionAttribute1,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pextensionAttribute1,ppValue[z]);
								}
							}

							else if(!strcmp(pAttribute, "streetAddress"))
							{
								strcpy(pstreetAddress,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pstreetAddress,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "l"))
							{
								strcpy(pl,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pl,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "st"))
							{
								strcpy(pst,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pst,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "telephoneNumber"))
							{
								strcpy(ptelephoneNumber,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(ptelephoneNumber,ppValue[z]);
								}
							}
							else if(!strcmp(pAttribute, "mail"))
							{
								strcpy(pmail,(const char*)*ppValue);
								// Output more values if available
								ULONG z;
								for (z = 1; z < iValue; z++)
								{
									strcat(pmail,ppValue[z]);
								}
								GetConnected(psAMAccountName, pgivenName, psn,pinitials,pdisplayName, pmail, pdepartment, 
								pphysicalDeliveryOfficeName, ptitle, pstreetAddress, pl, pst, ptelephoneNumber,pextensionAttribute1,
								SERVER ,UID, PWD, DATABASE);
							}
#endif //if 1

							// Output the first attribute value
							printf(": %s", (const char*)*ppValue);

							// Output more values if available
							ULONG z;
							for (z = 1; z < iValue; z++)
							{
								printf(", %s", ppValue[z]);
							}
						}
					}
					printf("\n");
			}//end of if
					// Free memory.
					if (ppValue != NULL)
						ldap_value_free(ppValue);
					ppValue = NULL;
					ldap_memfree(pAttribute);
	
					// Get next attribute name.
					pAttribute = ldap_next_attribute(
						pLdapConnection,   // Session Handle
						pEntry,            // Current entry
						pBer);             // Current BerElement
					//printf("\n");
				
			}

		}//end of for loops
			//} while (morePages == LDAP_TRUE);
		//} while (morePages == TRUE);

		if (pBer != NULL)
			ber_free(pBer, 0);
		pBer = NULL;


		//----------------------------------------------------------
		// Normal cleanup and exit.
		//----------------------------------------------------------
		//ldap_unbind(pLdapConnection);
		ldap_msgfree(pSearchResult);
		ldap_value_free(ppValue);

		} while (morePages == TRUE);

		ber_bvfree(cookie);
		cookie = NULL;

		ldap_unbind(pLdapConnection);
		//fclose(fp);

		return 0;
#if 0
	FatalExit:
		if (pLdapConnection != NULL)
			ldap_unbind_s(pLdapConnection);
		printf("\n\nERROR: 0x%x\n", returnCode);
		return returnCode;		
#endif
}

void GetConnected(char* samaccountname, char* givenname, char* sn,char* middlename, char* Displayname, char* Mail, char* Department, char* physicalDeliveryOfficeName, char* Title, char* streetAddress, char* l, char* st, char* telephoneNumber, char* pextensionAttribute1, char* SERVER , char* UID, char* PWD, char* DATABASE)
{
    SQLHANDLE henv;
    SQLRETURN rc;
    SQLHANDLE hconn;
    SQLSMALLINT bufsize=0;
    SQLINTEGER nativeerror=0;
    SQLSMALLINT textlen=0;
    unsigned char connStrOut[256];
    //SQLWCHAR sqlstate[32];
	SQLCHAR sqlstate[32];
    //SQLWCHAR message[256];
	SQLCHAR message[256];
 
    rc = SQLAllocEnv(&henv);
    if (rc != SQL_SUCCESS)
    {
        printf("\nSQLAllocEnv call failed.");
        return;
    }
 
    rc = SQLAllocHandle(SQL_HANDLE_DBC, henv, &hconn);
    if (rc != SQL_SUCCESS)
    {
        SQLFreeHandle(SQL_HANDLE_ENV, henv);
        printf("\nSQLAllocHandle call failed.");
        return;
    }
 
    //rc = SQLDriverConnect(hconn, NULL, (SQLWCHAR*)TEXT("DRIVER=SQL Server;SERVER=MyServer,1433;UID=Administrator;PWD=Pass;"), SQL_NTS, NULL, 256, &bufsize, SQL_DRIVER_NOPROMPT);
	//rc = SQLDriverConnect(hconn, NULL,(SQLCHAR*)TEXT("DRIVER=SQL Server;SERVER=MyServer,1433;UID=Administrator;PWD=Pass;"), SQL_NTS, NULL, 256, &bufsize, SQL_DRIVER_NOPROMPT);
	 //char* SERVER , char* UID, char* PWD, char* DATABASE
	//rc = SQLDriverConnect(hconn, NULL,(SQLCHAR*)TEXT("DRIVER=SQL Server;SERVER=127.0.0.1,1433;UID=sa;PWD=sa123;DATABASE=LM120d"),
	//char pConnString = "DRIVER=SQL Server;SERVER=";
	std::string ConnString = "DRIVER=SQL Server;SERVER=";
	ConnString = ConnString + SERVER;
	ConnString = ConnString + ",1433;UID=";
	ConnString = ConnString + UID;
	ConnString = ConnString + ";PWD=";
	ConnString = ConnString + PWD;
	ConnString = ConnString + ";DATABASE=";
	ConnString = ConnString + DATABASE;
	//rc = SQLDriverConnect(hconn, NULL,(SQLCHAR*)TEXT("DRIVER=SQL Server;SERVER=127.0.0.1,1433;UID=sa;PWD=sa123;DATABASE=LM120d"),
	rc = SQLDriverConnect(hconn, NULL,(SQLCHAR*)TEXT(ConnString.c_str()),
		SQL_NTS, NULL, 256, &bufsize, SQL_DRIVER_NOPROMPT);
 
    if (bufsize!=0)
    {
        //printf("Connected successfully.\n");

 
  //strcpy((char*)stmt_handle,"INSERT INTO members_ (Id, Float_Point, Date_Field, Text_Field) VALUES(?,?,?,?);");


/*SQLPrepare(stmt_handle,
			"select * from mytable where mycol = ?", SQL_NTS);*/
		SQLHSTMT  stmt_handle = SQL_NULL_HSTMT;  // Statement handle
		int retcode = SQLAllocHandle(SQL_HANDLE_STMT, hconn, &stmt_handle);
		//int ret1 = SQLExecDirect(stmt_handle, (SQLCHAR*)"select * from members_", SQL_NTS);
		

		SQLINTEGER  i;                /* sqlcli.h has "typedef long SQLINTEGER" */
		SQLINTEGER  i_indicator;

		/*
		int ret5 = SQLPrepare(stmt_handle,
			(SQLCHAR*) "INSERT INTO tableNew (samaccountname, givenname, sn,middlename,Displayname,Mail, Department,physicalDeliveryOfficeName, Title,streetAddress,l,st,telephoneNumber) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);", SQL_NTS);
			//(SQLCHAR*) "INSERT INTO tableNew (samaccountname_, givenname, sn, middlename, Displayname,Mail, Department, physicalDeliveryOfficeName, Title) VALUES(?,?,?,?,?,?,?,?,?);", SQL_NTS);
		*/
		/*
		int ret5 = SQLPrepare(stmt_handle,
			(SQLCHAR*) "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = N'tableNew';", SQL_NTS);
		if(ret5 == 0)
		{
			printf("successss\n");
			return;
		}
		*/

		int ret5 = SQLPrepare(stmt_handle,
			(SQLCHAR*) "if not exists(SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'tableNew') CREATE TABLE tableNew (samaccountname VARCHAR(100) , givenname VARCHAR(100), sn  VARCHAR(100), middlename VARCHAR(100), Displayname VARCHAR(100), Mail VARCHAR(100), Department VARCHAR(100), physicalDeliveryOfficeName VARCHAR(100),Title VARCHAR(100), streetAddress VARCHAR(100), l VARCHAR(100),	st VARCHAR(100), telephoneNumber VARCHAR(100) , Dept_Code char );", SQL_NTS);
		//	(SQLCHAR*) "CREATE TABLE tableNew (samaccountname VARCHAR(100) , givenname VARCHAR(100), sn  VARCHAR(100), middlename VARCHAR(100), Displayname VARCHAR(100), Mail VARCHAR(100), Department VARCHAR(100), physicalDeliveryOfficeName VARCHAR(100),Title VARCHAR(100), streetAddress VARCHAR(100), l VARCHAR(100),	st VARCHAR(100), telephoneNumber VARCHAR(100));", SQL_NTS);
		ret5 = SQLExecute(stmt_handle);
		if(SQL_SUCCESS != ret5)
		{
			printf("Required Table in Database not created\n");
			return;
		}
		//SQLFreeHandle(SQL_HANDLE_STMT, stmt_handle );

#if 1
		//(SQLCHAR*) "INSERT INTO tableNew (samaccountname_, givenname, sn, middlename, Displayname,Mail, Department, physicalDeliveryOfficeName, Title) VALUES(?,?,?,?,?,?,?,?,?);", SQL_NTS);

		int ret6 = SQLPrepare(stmt_handle, (SQLCHAR*) "SELECT MAIL FROM tableNew WHERE MAIL = ?;", SQL_NTS);
		//int ret6 = SQLPrepare(stmt_handle, (SQLCHAR*) "SELECT FROM tableNew WHERE mail = ?;");
		retcode = SQLBindParameter(stmt_handle, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
								SQL_VARCHAR, 50, 0, Mail, strlen(Mail), NULL);

		ret6 = SQLExecute(stmt_handle);
		//ret6 = SQLExecute(stmt_handle);
		//if(SQL_SUCCESS == ret6)
		//if (SQLFetch(stmt_handle) == SQL_SUCCESS)
		SQLRETURN  retFetch = SQLFetch(stmt_handle);
		//if (SQLFetch(stmt_handle) == SQL_SUCCESS_WITH_INFO)
		//if (retFetch == SQL_SUCCESS_WITH_INFO)
		if (SQL_SUCCEEDED(retFetch)) 
		{
			//printf("This email : %s : already exist!!\n", Mail );
			ret6 = SQLFreeStmt(stmt_handle, SQL_CLOSE);  
			ret6 = SQLFreeStmt(stmt_handle, SQL_UNBIND);  
			ret6 = SQLFreeStmt(stmt_handle, SQL_RESET_PARAMS);  
			SQLDisconnect(hconn);
			//SQLFreeHandle(SQL_HANDLE_STMT, stmt_handle );
			//return;
		}
		else
#endif 
		{
	    ret6 = SQLFreeStmt(stmt_handle, SQL_CLOSE);  
	    ret6 = SQLFreeStmt(stmt_handle, SQL_UNBIND);  
        ret6 = SQLFreeStmt(stmt_handle, SQL_RESET_PARAMS);  
		//SQLFreeHandle(SQL_HANDLE_STMT, stmt_handle );
		SQLLEN len2 = 0; //strlen(ptr);
		SQLLEN len3 = 0; //strlen(ptr);
		int ret3 = SQLPrepare(stmt_handle,
			(SQLCHAR*) "INSERT INTO tableNew (samaccountname, givenname, sn,middlename,Displayname,Mail, Department,physicalDeliveryOfficeName, Title,streetAddress,l,st,telephoneNumber,Dept_Code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?);", SQL_NTS);
			//(SQLCHAR*) "INSERT INTO tableNew (samaccountname_, givenname, sn, middlename, Displayname,Mail, Department, physicalDeliveryOfficeName, Title) VALUES(?,?,?,?,?,?,?,?,?);", SQL_NTS);
		retcode = SQLBindParameter(stmt_handle, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_LONGVARCHAR, 4, 0, ptr111, 100, &len2);	
								SQL_VARCHAR, 50, 0, samaccountname, strlen(samaccountname), NULL);

		
		retcode = SQLBindParameter(stmt_handle, 2, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, givenname, strlen(givenname), NULL);
		

		retcode = SQLBindParameter(stmt_handle, 3, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, sn, strlen(sn), NULL);

		retcode = SQLBindParameter(stmt_handle, 4, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, middlename, strlen(middlename), NULL);

		retcode = SQLBindParameter(stmt_handle, 5, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, Displayname, strlen(Displayname), NULL);

		//We probably wont need this Bind Since its already called above
		retcode = SQLBindParameter(stmt_handle, 6, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, Mail, strlen(Mail), NULL);

		retcode = SQLBindParameter(stmt_handle, 7, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, Department, strlen(Department), NULL);

		retcode = SQLBindParameter(stmt_handle, 8, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, physicalDeliveryOfficeName, strlen(physicalDeliveryOfficeName), NULL);

		retcode = SQLBindParameter(stmt_handle, 9, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, Title, strlen(Title), NULL);


		retcode = SQLBindParameter(stmt_handle, 10, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, streetAddress, strlen(streetAddress), NULL);

		retcode = SQLBindParameter(stmt_handle, 11, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, l, strlen(l), NULL);

		retcode = SQLBindParameter(stmt_handle,12, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, st, strlen(st), NULL);

		retcode = SQLBindParameter(stmt_handle, 13, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_VARCHAR, 50, 0, telephoneNumber, strlen(telephoneNumber), NULL);

		//For Dept_Code Column
		retcode = SQLBindParameter(stmt_handle, 14, SQL_PARAM_INPUT, SQL_C_CHAR,
			                    //SQL_VARCHAR, 4, 0, ptr111, 100, &len2);
								SQL_CHAR, 50, 0, pextensionAttribute1, strlen(pextensionAttribute1), NULL);


		int ret4 = SQLExecute(stmt_handle);
		if(SQL_SUCCESS == ret4)
			//printf("SQLExecute success\n");
		
		/*
		int ret1 = SQLExecute(stmt_handle);
		if(SQL_SUCCESS == ret1)
			printf("SQLExecute success\n");
		*/

        SQLDisconnect(hconn);
	  }//select query for if exists
    }
    else
    {
        rc = SQLGetDiagRec(SQL_HANDLE_DBC, hconn, 1, sqlstate, &nativeerror, message, 256, &textlen);
 
        printf("SQLDriverConnect failed.\n");
        if (rc!=SQL_ERROR)
            printf("%s=%s\n", (CHAR *)sqlstate, (CHAR *)message);
    }
 
    SQLFreeHandle(SQL_HANDLE_DBC, hconn);
    SQLFreeHandle(SQL_HANDLE_ENV, henv);
}


//int main()
int main(int argc, char** argv)
{

	//if (!(MyLDAPSearch("ohio","ohio")))
	//if (!(MyLDAPSearch("administrator", "abc@1234#")))
	//if (!(MyLDAPSearch("administrator", "abc@1234#")))
	//if (!(MyLDAPSearch("administrator", "87UxmymR.q")))
	//WIN-VKI3OAPV1BL.ohioplugin8.net
	//"OU=MyTestOU,DC=ohioplugin8,DC=net"
	// "(objectClass=user)"
	//if(argc < 6)
	if(argc < 10)
	{
				printf("Please make sure all required parameters are Passed!!\n");
				return 1;
	}
	//char* SERVER , char* UID, char* PWD, char* DATABASE);)
	if (!(MyLDAPSearch(argv[1], argv[2], argv[3],argv[4], argv[5], argv[6], argv[7], argv[8], argv[9]))) //login,password
	//if (!(MyLDAPSearch("ohioadplugin.net\administrator", "abc@1234#")))
			printf("fine!!\n");
	else
		printf("Not fine!!\n");
		
}