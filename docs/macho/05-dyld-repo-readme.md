# dyld — Apple's open-source dynamic linker

> **Source:** <https://github.com/opensource-apple/dyld>  
> **Fetched:** 2026-08-17  
> **License:** Content © respective upstream authors.
Reproduced here as a developer reference for the mac-ify
codebase. The Mach-O format itself is publicly documented
in `<mach-o/loader.h>` and Apple's open documentation.

---

Skip to content

## Navigation Menu

[](</>)

[Sign in](</login?return_to=https%3A%2F%2Fgithub.com%2Fopensource-apple%2Fdyld>)

Appearance settings

  * Platform

    * AI CODE CREATION
      * [GitHub CopilotWrite better code with AI](<https://github.com/features/copilot>)
      * [GitHub Copilot appDirect agents from issue to merge](<https://github.com/features/ai/github-app>)
      * [MCP RegistryIntegrate external tools](<https://github.com/mcp>)

    * DEVELOPER WORKFLOWS
      * [ActionsAutomate any workflow](<https://github.com/features/actions>)
      * [CodespacesInstant dev environments](<https://github.com/features/codespaces>)
      * [IssuesPlan and track work](<https://github.com/features/issues>)
      * [Code ReviewManage code changes](<https://github.com/features/code-review>)
      * [Code QualityEnforce quality at merge](<https://github.com/features/code-quality>)

    * APPLICATION SECURITY
      * [GitHub Advanced SecurityFind and fix vulnerabilities](<https://github.com/security/advanced-security>)
      * [Code securitySecure your code as you build](<https://github.com/security/advanced-security/code-security>)
      * [Secret protectionStop leaks before they start](<https://github.com/security/advanced-security/secret-protection>)

    * EXPLORE
      * [Why GitHub](<https://github.com/why-github>)
      * [Documentation](<https://docs.github.com>)
      * [Blog](<https://github.blog>)
      * [Changelog](<https://github.blog/changelog>)
      * [Marketplace](<https://github.com/marketplace>)

[View all features](<https://github.com/features>)

  * Solutions

    * BY COMPANY SIZE
      * [Enterprises](<https://github.com/enterprise>)
      * [Small and medium teams](<https://github.com/team>)
      * [Startups](<https://github.com/enterprise/startups>)
      * [Nonprofits](<https://github.com/solutions/industry/nonprofits>)

    * BY USE CASE
      * [App Modernization](<https://github.com/solutions/use-case/app-modernization>)
      * [DevSecOps](<https://github.com/solutions/use-case/devsecops>)
      * [DevOps](<https://github.com/solutions/use-case/devops>)
      * [CI/CD](<https://github.com/solutions/use-case/ci-cd>)
      * [View all use cases](<https://github.com/solutions/use-case>)

    * BY INDUSTRY
      * [Healthcare](<https://github.com/solutions/industry/healthcare>)
      * [Financial services](<https://github.com/solutions/industry/financial-services>)
      * [Manufacturing](<https://github.com/solutions/industry/manufacturing>)
      * [Government](<https://github.com/solutions/industry/government>)
      * [View all industries](<https://github.com/solutions/industry>)

[View all solutions](<https://github.com/solutions>)

  * Resources

    * EXPLORE BY TOPIC
      * [AI](<https://github.com/resources/articles?topic=ai>)
      * [Software Development](<https://github.com/resources/articles?topic=software-development>)
      * [DevOps](<https://github.com/resources/articles?topic=devops>)
      * [Security](<https://github.com/resources/articles?topic=security>)
      * [View all topics](<https://github.com/resources/articles>)

    * EXPLORE BY TYPE
      * [Customer stories](<https://github.com/customer-stories>)
      * [Events & webinars](<https://github.com/resources/events>)
      * [Ebooks & reports](<https://github.com/resources/whitepapers>)
      * [Business insights](<https://github.com/solutions/executive-insights>)
      * [GitHub Skills](<https://skills.github.com>)

    * SUPPORT & SERVICES
      * [Documentation](<https://docs.github.com>)
      * [Customer support](<https://support.github.com>)
      * [Community forum](<https://github.com/orgs/community/discussions>)
      * [Trust center](<https://github.com/trust-center>)
      * [Partners](<https://github.com/partners>)

[View all resources](<https://github.com/resources>)

  * Open Source

    * COMMUNITY
      * [GitHub SponsorsFund open source developers](<https://github.com/open-source/sponsors>)

    * PROGRAMS
      * [Security Lab](<https://securitylab.github.com>)
      * [Maintainer Community](<https://maintainers.github.com>)
      * [Accelerator](<https://github.com/open-source/accelerator>)
      * [GitHub Stars](<https://stars.github.com>)
      * [Archive Program](<https://archiveprogram.github.com>)

    * REPOSITORIES
      * [Topics](<https://github.com/topics>)
      * [Trending](<https://github.com/trending>)
      * [Collections](<https://github.com/collections>)

  * Enterprise

    * ENTERPRISE SOLUTIONS
      * [Enterprise platformAI-powered developer platform](<https://github.com/enterprise>)

    * AVAILABLE ADD-ONS
      * [GitHub Advanced SecurityEnterprise-grade security features](<https://github.com/security/advanced-security>)
      * [Copilot for BusinessEnterprise-grade AI features](<https://github.com/features/copilot/copilot-business>)
      * [Premium SupportEnterprise-grade 24/7 support](<https://github.com/enterprise/premium-support>)

  * [Pricing](<https://github.com/pricing>)



Search`/`

[Sign in](</login?return_to=https%3A%2F%2Fgithub.com%2Fopensource-apple%2Fdyld>)

[Sign up](</signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F%3Cuser-name%3E%2F%3Crepo-name%3E&source=header-repo&source_repo=opensource-apple%2Fdyld>)

Appearance settings

You signed in with another tab or window. [Reload](<>) to refresh your session. You signed out in another tab or window. [Reload](<>) to refresh your session. You switched accounts on another tab or window. [Reload](<>) to refresh your session. Dismiss alert

{{ message }}

[ opensource-apple ](</opensource-apple>) / **[dyld](</opensource-apple/dyld>) ** Public

  * [ Notifications ](</login?return_to=%2Fopensource-apple%2Fdyld>) You must be signed in to change notification settings
  * [ Fork 133 ](</login?return_to=%2Fopensource-apple%2Fdyld>)
  * [ Star  662 ](</login?return_to=%2Fopensource-apple%2Fdyld>)




  * [ Code ](</opensource-apple/dyld>)
  * [ Issues 2 ](</opensource-apple/dyld/issues>)
  * [ Pull requests 0 ](</opensource-apple/dyld/pulls>)
  * [ Actions ](</opensource-apple/dyld/actions>)
  * [ Projects ](</opensource-apple/dyld/projects>)
  * [ Wiki ](</opensource-apple/dyld/wiki>)
  * [ Security and quality 0 ](</opensource-apple/dyld/security>)
  * [ Insights ](</opensource-apple/dyld/pulse>)



Additional navigation options

  * [ Code  ](</opensource-apple/dyld>)
  * [ Issues  ](</opensource-apple/dyld/issues>)
  * [ Pull requests  ](</opensource-apple/dyld/pulls>)
  * [ Actions  ](</opensource-apple/dyld/actions>)
  * [ Projects  ](</opensource-apple/dyld/projects>)
  * [ Wiki  ](</opensource-apple/dyld/wiki>)
  * [ Security and quality  ](</opensource-apple/dyld/security>)
  * [ Insights  ](</opensource-apple/dyld/pulse>)



[](</opensource-apple/dyld>)

master

[**1** Branch](</opensource-apple/dyld/branches>)[**0** Tags](</opensource-apple/dyld/tags>)

[](</opensource-apple/dyld/branches>)[](</opensource-apple/dyld/tags>)

Go to file

Code

Open more actions menu

## Folders and files

Name| Name| Last commit message| Last commit date  
---|---|---|---  
  
## Latest commit

Apple Open Sourceand[opensource-apple](</opensource-apple/dyld/commits?author=opensource-apple>)[Version 360.18](</opensource-apple/dyld/commit/3f928f32597888c5eac6003b9199d972d49857b5>)Open commit detailsDec 21, 2015[3f928f3](</opensource-apple/dyld/commit/3f928f32597888c5eac6003b9199d972d49857b5>) · Dec 21, 2015

## History

[24 Commits](</opensource-apple/dyld/commits/master/>)Open commit details[](</opensource-apple/dyld/commits/master/>)24 Commits  
[bin](</opensource-apple/dyld/tree/master/bin> "bin")| [bin](</opensource-apple/dyld/tree/master/bin> "bin")| [Version 195.5](</opensource-apple/dyld/commit/f61dbef5a1b1f2d462069972d0c12743beab39ad> "Version 195.5

http://opensource.apple.com/tarballs/dyld/dyld-195.5.tar.gz")| Jul 31, 2014  
[configs](</opensource-apple/dyld/tree/master/configs> "configs")| [configs](</opensource-apple/dyld/tree/master/configs> "configs")| [Version 360.14](</opensource-apple/dyld/commit/195030646877261f0c8c7ad8b001f52d6a26f514> "Version 360.14

http://opensource.apple.com/tarballs/dyld/dyld-360.14.tar.gz")| Dec 8, 2015  
[doc](</opensource-apple/dyld/tree/master/doc> "doc")| [doc](</opensource-apple/dyld/tree/master/doc> "doc")| [Version 353.2.1](</opensource-apple/dyld/commit/3e50998b5347e9732b0789c7b639f7494aa20a2d> "Version 353.2.1

http://opensource.apple.com/tarballs/dyld/dyld-353.2.1.tar.gz")| Nov 7, 2014  
[dyld.xcodeproj](</opensource-apple/dyld/tree/master/dyld.xcodeproj> "dyld.xcodeproj")| [dyld.xcodeproj](</opensource-apple/dyld/tree/master/dyld.xcodeproj> "dyld.xcodeproj")| [Version 360.14](</opensource-apple/dyld/commit/195030646877261f0c8c7ad8b001f52d6a26f514> "Version 360.14

http://opensource.apple.com/tarballs/dyld/dyld-360.14.tar.gz")| Dec 8, 2015  
[include](</opensource-apple/dyld/tree/master/include> "include")| [include](</opensource-apple/dyld/tree/master/include> "include")| [Version 360.14](</opensource-apple/dyld/commit/195030646877261f0c8c7ad8b001f52d6a26f514> "Version 360.14

http://opensource.apple.com/tarballs/dyld/dyld-360.14.tar.gz")| Dec 8, 2015  
[launch-cache](</opensource-apple/dyld/tree/master/launch-cache> "launch-cache")| [launch-cache](</opensource-apple/dyld/tree/master/launch-cache> "launch-cache")| [Version 360.14](</opensource-apple/dyld/commit/195030646877261f0c8c7ad8b001f52d6a26f514> "Version 360.14

http://opensource.apple.com/tarballs/dyld/dyld-360.14.tar.gz")| Dec 8, 2015  
[src](</opensource-apple/dyld/tree/master/src> "src")| [src](</opensource-apple/dyld/tree/master/src> "src")| [Version 360.18](</opensource-apple/dyld/commit/3f928f32597888c5eac6003b9199d972d49857b5> "Version 360.18

http://opensource.apple.com/tarballs/dyld/dyld-360.18.tar.gz")| Dec 21, 2015  
[unit-tests](</opensource-apple/dyld/tree/master/unit-tests> "unit-tests")| [unit-tests](</opensource-apple/dyld/tree/master/unit-tests> "unit-tests")| [Version 360.14](</opensource-apple/dyld/commit/195030646877261f0c8c7ad8b001f52d6a26f514> "Version 360.14

http://opensource.apple.com/tarballs/dyld/dyld-360.14.tar.gz")| Dec 8, 2015  
[APPLE_LICENSE](</opensource-apple/dyld/blob/master/APPLE_LICENSE> "APPLE_LICENSE")| [APPLE_LICENSE](</opensource-apple/dyld/blob/master/APPLE_LICENSE> "APPLE_LICENSE")| [Version 43](</opensource-apple/dyld/commit/e543740e224529b5218f19b1e2144d9e10a41d20> "Version 43

http://opensource.apple.com/tarballs/dyld/dyld-43.tar.gz")| Jul 31, 2014  
[dyld_sim-entitlements.plist](</opensource-apple/dyld/blob/master/dyld_sim-entitlements.plist> "dyld_sim-entitlements.plist")| [dyld_sim-entitlements.plist](</opensource-apple/dyld/blob/master/dyld_sim-entitlements.plist> "dyld_sim-entitlements.plist")| [Version 353.2.1](</opensource-apple/dyld/commit/3e50998b5347e9732b0789c7b639f7494aa20a2d> "Version 353.2.1

http://opensource.apple.com/tarballs/dyld/dyld-353.2.1.tar.gz")| Nov 7, 2014  
View all files  
  
## Repository files navigation

  *   * License



More items
[code]
    APPLE PUBLIC SOURCE LICENSE
    Version 2.0 - August 6, 2003
    
    Please read this License carefully before downloading this software.
    By downloading or using this software, you are agreeing to be bound by
    the terms of this License. If you do not or cannot agree to the terms
    of this License, please do not download or use the software.
    
    1. General; Definitions. This License applies to any program or other
    work which Apple Computer, Inc. ("Apple") makes publicly available and
    which contains a notice placed by Apple identifying such program or
    work as "Original Code" and stating that it is subject to the terms of
    this Apple Public Source License version 2.0 ("License"). As used in
    this License:
    
    1.1 "Applicable Patent Rights" mean: (a) in the case where Apple is
    the grantor of rights, (i) claims of patents that are now or hereafter
    acquired, owned by or assigned to Apple and (ii) that cover subject
    matter contained in the Original Code, but only to the extent
    necessary to use, reproduce and/or distribute the Original Code
    without infringement; and (b) in the case where You are the grantor of
    rights, (i) claims of patents that are now or hereafter acquired,
    owned by or assigned to You and (ii) that cover subject matter in Your
    Modifications, taken alone or in combination with Original Code.
    
    1.2 "Contributor" means any person or entity that creates or
    contributes to the creation of Modifications.
    
    1.3 "Covered Code" means the Original Code, Modifications, the
    combination of Original Code and any Modifications, and/or any
    respective portions thereof.
    
    1.4 "Externally Deploy" means: (a) to sublicense, distribute or
    otherwise make Covered Code available, directly or indirectly, to
    anyone other than You; and/or (b) to use Covered Code, alone or as
    part of a Larger Work, in any way to provide a service, including but
    not limited to delivery of content, through electronic communication
    with a client other than You.
    
    1.5 "Larger Work" means a work which combines Covered Code or portions
    thereof with code not governed by the terms of this License.
    
    1.6 "Modifications" mean any addition to, deletion from, and/or change
    to, the substance and/or structure of the Original Code, any previous
    Modifications, the combination of Original Code and any previous
    Modifications, and/or any respective portions thereof. When code is
    released as a series of files, a Modification is: (a) any addition to
    or deletion from the contents of a file containing Covered Code;
    and/or (b) any new file or other representation of computer program
    statements that contains any part of Covered Code.
    
    1.7 "Original Code" means (a) the Source Code of a program or other
    work as originally made available by Apple under this License,
    including the Source Code of any updates or upgrades to such programs
    or works made available by Apple under this License, and that has been
    expressly identified by Apple as such in the header file(s) of such
    work; and (b) the object code compiled from such Source Code and
    originally made available by Apple under this License.
    
    1.8 "Source Code" means the human readable form of a program or other
    work that is suitable for making modifications to it, including all
    modules it contains, plus any associated interface definition files,
    scripts used to control compilation and installation of an executable
    (object code).
    
    1.9 "You" or "Your" means an individual or a legal entity exercising
    rights under this License. For legal entities, "You" or "Your"
    includes any entity which controls, is controlled by, or is under
    common control with, You, where "control" means (a) the power, direct
    or indirect, to cause the direction or management of such entity,
    whether by contract or otherwise, or (b) ownership of fifty percent
    (50%) or more of the outstanding shares or beneficial ownership of
    such entity.
    
    2. Permitted Uses; Conditions & Restrictions. Subject to the terms
    and conditions of this License, Apple hereby grants You, effective on
    the date You accept this License and download the Original Code, a
    world-wide, royalty-free, non-exclusive license, to the extent of
    Apple's Applicable Patent Rights and copyrights covering the Original
    Code, to do the following:
    
    2.1 Unmodified Code. You may use, reproduce, display, perform,
    internally distribute within Your organization, and Externally Deploy
    verbatim, unmodified copies of the Original Code, for commercial or
    non-commercial purposes, provided that in each instance:
    
    (a) You must retain and reproduce in all copies of Original Code the
    copyright and other proprietary notices and disclaimers of Apple as
    they appear in the Original Code, and keep intact all notices in the
    Original Code that refer to this License; and
    
    (b) You must include a copy of this License with every copy of Source
    Code of Covered Code and documentation You distribute or Externally
    Deploy, and You may not offer or impose any terms on such Source Code
    that alter or restrict this License or the recipients' rights
    hereunder, except as permitted under Section 6.
    
    2.2 Modified Code. You may modify Covered Code and use, reproduce,
    display, perform, internally distribute within Your organization, and
    Externally Deploy Your Modifications and Covered Code, for commercial
    or non-commercial purposes, provided that in each instance You also
    meet all of these conditions:
    
    (a) You must satisfy all the conditions of Section 2.1 with respect to
    the Source Code of the Covered Code;
    
    (b) You must duplicate, to the extent it does not already exist, the
    notice in Exhibit A in each file of the Source Code of all Your
    Modifications, and cause the modified files to carry prominent notices
    stating that You changed the files and the date of any change; and
    
    (c) If You Externally Deploy Your Modifications, You must make
    Source Code of all Your Externally Deployed Modifications either
    available to those to whom You have Externally Deployed Your
    Modifications, or publicly available. Source Code of Your Externally
    Deployed Modifications must be released under the terms set forth in
    this License, including the license grants set forth in Section 3
    below, for as long as you Externally Deploy the Covered Code or twelve
    (12) months from the date of initial External Deployment, whichever is
    longer. You should preferably distribute the Source Code of Your
    Externally Deployed Modifications electronically (e.g. download from a
    web site).
    
    2.3 Distribution of Executable Versions. In addition, if You
    Externally Deploy Covered Code (Original Code and/or Modifications) in
    object code, executable form only, You must include a prominent
    notice, in the code itself as well as in related documentation,
    stating that Source Code of the Covered Code is available under the
    terms of this License with information on how and where to obtain such
    Source Code.
    
    2.4 Third Party Rights. You expressly acknowledge and agree that
    although Apple and each Contributor grants the licenses to their
    respective portions of the Covered Code set forth herein, no
    assurances are provided by Apple or any Contributor that the Covered
    Code does not infringe the patent or other intellectual property
    rights of any other entity. Apple and each Contributor disclaim any
    liability to You for claims brought by any other entity based on
    infringement of intellectual property rights or otherwise. As a
    condition to exercising the rights and licenses granted hereunder, You
    hereby assume sole responsibility to secure any other intellectual
    property rights needed, if any. For example, if a third party patent
    license is required to allow You to distribute the Covered Code, it is
    Your responsibility to acquire that license before distributing the
    Covered Code.
    
    3. Your Grants. In consideration of, and as a condition to, the
    licenses granted to You under this License, You hereby grant to any
    person or entity receiving or distributing Covered Code under this
    License a non-exclusive, royalty-free, perpetual, irrevocable license,
    under Your Applicable Patent Rights and other intellectual property
    rights (other than patent) owned or controlled by You, to use,
    reproduce, display, perform, modify, sublicense, distribute and
    Externally Deploy Your Modifications of the same scope and extent as
    Apple's licenses under Sections 2.1 and 2.2 above.
    
    4. Larger Works. You may create a Larger Work by combining Covered
    Code with other code not governed by the terms of this License and
    distribute the Larger Work as a single product. In each such instance,
    You must make sure the requirements of this License are fulfilled for
    the Covered Code or any portion thereof.
    
    5. Limitations on Patent License. Except as expressly stated in
    Section 2, no other patent rights, express or implied, are granted by
    Apple herein. Modifications and/or Larger Works may require additional
    patent licenses from Apple which Apple may grant in its sole
    discretion.
    
    6. Additional Terms. You may choose to offer, and to charge a fee for,
    warranty, support, indemnity or liability obligations and/or other
    rights consistent with the scope of the license granted herein
    ("Additional Terms") to one or more recipients of Covered Code.
    However, You may do so only on Your own behalf and as Your sole
    responsibility, and not on behalf of Apple or any Contributor. You
    must obtain the recipient's agreement that any such Additional Terms
    are offered by You alone, and You hereby agree to indemnify, defend
    and hold Apple and every Contributor harmless for any liability
    incurred by or claims asserted against Apple or such Contributor by
    reason of any such Additional Terms.
    
    7. Versions of the License. Apple may publish revised and/or new
    versions of this License from time to time. Each version will be given
    a distinguishing version number. Once Original Code has been published
    under a particular version of this License, You may continue to use it
    under the terms of that version. You may also choose to use such
    Original Code under the terms of any subsequent version of this
    License published by Apple. No one other than Apple has the right to
    modify the terms applicable to Covered Code created under this
    License.
    
    8. NO WARRANTY OR SUPPORT. The Covered Code may contain in whole or in
    part pre-release, untested, or not fully tested works. The Covered
    Code may contain errors that could cause failures or loss of data, and
    may be incomplete or contain inaccuracies. You expressly acknowledge
    and agree that use of the Covered Code, or any portion thereof, is at
    Your sole and entire risk. THE COVERED CODE IS PROVIDED "AS IS" AND
    WITHOUT WARRANTY, UPGRADES OR SUPPORT OF ANY KIND AND APPLE AND
    APPLE'S LICENSOR(S) (COLLECTIVELY REFERRED TO AS "APPLE" FOR THE
    PURPOSES OF SECTIONS 8 AND 9) AND ALL CONTRIBUTORS EXPRESSLY DISCLAIM
    ALL WARRANTIES AND/OR CONDITIONS, EXPRESS OR IMPLIED, INCLUDING, BUT
    NOT LIMITED TO, THE IMPLIED WARRANTIES AND/OR CONDITIONS OF
    MERCHANTABILITY, OF SATISFACTORY QUALITY, OF FITNESS FOR A PARTICULAR
    PURPOSE, OF ACCURACY, OF QUIET ENJOYMENT, AND NONINFRINGEMENT OF THIRD
    PARTY RIGHTS. APPLE AND EACH CONTRIBUTOR DOES NOT WARRANT AGAINST
    INTERFERENCE WITH YOUR ENJOYMENT OF THE COVERED CODE, THAT THE
    FUNCTIONS CONTAINED IN THE COVERED CODE WILL MEET YOUR REQUIREMENTS,
    THAT THE OPERATION OF THE COVERED CODE WILL BE UNINTERRUPTED OR
    ERROR-FREE, OR THAT DEFECTS IN THE COVERED CODE WILL BE CORRECTED. NO
    ORAL OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE, AN APPLE
    AUTHORIZED REPRESENTATIVE OR ANY CONTRIBUTOR SHALL CREATE A WARRANTY.
    You acknowledge that the Covered Code is not intended for use in the
    operation of nuclear facilities, aircraft navigation, communication
    systems, or air traffic control machines in which case the failure of
    the Covered Code could lead to death, personal injury, or severe
    physical or environmental damage.
    
    9. LIMITATION OF LIABILITY. TO THE EXTENT NOT PROHIBITED BY LAW, IN NO
    EVENT SHALL APPLE OR ANY CONTRIBUTOR BE LIABLE FOR ANY INCIDENTAL,
    SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES ARISING OUT OF OR RELATING
    TO THIS LICENSE OR YOUR USE OR INABILITY TO USE THE COVERED CODE, OR
    ANY PORTION THEREOF, WHETHER UNDER A THEORY OF CONTRACT, WARRANTY,
    TORT (INCLUDING NEGLIGENCE), PRODUCTS LIABILITY OR OTHERWISE, EVEN IF
    APPLE OR SUCH CONTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
    DAMAGES AND NOTWITHSTANDING THE FAILURE OF ESSENTIAL PURPOSE OF ANY
    REMEDY. SOME JURISDICTIONS DO NOT ALLOW THE LIMITATION OF LIABILITY OF
    INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THIS LIMITATION MAY NOT APPLY
    TO YOU. In no event shall Apple's total liability to You for all
    damages (other than as may be required by applicable law) under this
    License exceed the amount of fifty dollars ($50.00).
    
    10. Trademarks. This License does not grant any rights to use the
    trademarks or trade names "Apple", "Apple Computer", "Mac", "Mac OS",
    "QuickTime", "QuickTime Streaming Server" or any other trademarks,
    service marks, logos or trade names belonging to Apple (collectively
    "Apple Marks") or to any trademark, service mark, logo or trade name
    belonging to any Contributor. You agree not to use any Apple Marks in
    or as part of the name of products derived from the Original Code or
    to endorse or promote products derived from the Original Code other
    than as expressly permitted by and in strict compliance at all times
    with Apple's third party trademark usage guidelines which are posted
    at <http://www.apple.com/legal/guidelinesfor3rdparties.html>.
    
    11. Ownership. Subject to the licenses granted under this License,
    each Contributor retains all rights, title and interest in and to any
    Modifications made by such Contributor. Apple retains all rights,
    title and interest in and to the Original Code and any Modifications
    made by or on behalf of Apple ("Apple Modifications"), and such Apple
    Modifications will not be automatically subject to this License. Apple
    may, at its sole discretion, choose to license such Apple
    Modifications under this License, or on different terms from those
    contained in this License or may choose not to license them at all.
    
    12. Termination.
    
    12.1 Termination. This License and the rights granted hereunder will
    terminate:
    
    (a) automatically without notice from Apple if You fail to comply with
    any term(s) of this License and fail to cure such breach within 30
    days of becoming aware of such breach;
    
    (b) immediately in the event of the circumstances described in Section
    13.5(b); or
    
    (c) automatically without notice from Apple if You, at any time during
    the term of this License, commence an action for patent infringement
    against Apple; provided that Apple did not first commence
    an action for patent infringement against You in that instance.
    
    12.2 Effect of Termination. Upon termination, You agree to immediately
    stop any further use, reproduction, modification, sublicensing and
    distribution of the Covered Code. All sublicenses to the Covered Code
    which have been properly granted prior to termination shall survive
    any termination of this License. Provisions which, by their nature,
    should remain in effect beyond the termination of this License shall
    survive, including but not limited to Sections 3, 5, 8, 9, 10, 11,
    12.2 and 13. No party will be liable to any other for compensation,
    indemnity or damages of any sort solely as a result of terminating
    this License in accordance with its terms, and termination of this
    License will be without prejudice to any other right or remedy of
    any party.
    
    13. Miscellaneous.
    
    13.1 Government End Users. The Covered Code is a "commercial item" as
    defined in FAR 2.101. Government software and technical data rights in
    the Covered Code include only those rights customarily provided to the
    public as defined in this License. This customary commercial license
    in technical data and software is provided in accordance with FAR
    12.211 (Technical Data) and 12.212 (Computer Software) and, for
    Department of Defense purchases, DFAR 252.227-7015 (Technical Data --
    Commercial Items) and 227.7202-3 (Rights in Commercial Computer
    Software or Computer Software Documentation). Accordingly, all U.S.
    Government End Users acquire Covered Code with only those rights set
    forth herein.
    
    13.2 Relationship of Parties. This License will not be construed as
    creating an agency, partnership, joint venture or any other form of
    legal association between or among You, Apple or any Contributor, and
    You will not represent to the contrary, whether expressly, by
    implication, appearance or otherwise.
    
    13.3 Independent Development. Nothing in this License will impair
    Apple's right to acquire, license, develop, have others develop for
    it, market and/or distribute technology or products that perform the
    same or similar functions as, or otherwise compete with,
    Modifications, Larger Works, technology or products that You may
    develop, produce, market or distribute.
    
    13.4 Waiver; Construction. Failure by Apple or any Contributor to
    enforce any provision of this License will not be deemed a waiver of
    future enforcement of that or any other provision. Any law or
    regulation which provides that the language of a contract shall be
    construed against the drafter will not apply to this License.
    
    13.5 Severability. (a) If for any reason a court of competent
    jurisdiction finds any provision of this License, or portion thereof,
    to be unenforceable, that provision of the License will be enforced to
    the maximum extent permissible so as to effect the economic benefits
    and intent of the parties, and the remainder of this License will
    continue in full force and effect. (b) Notwithstanding the foregoing,
    if applicable law prohibits or restricts You from fully and/or
    specifically complying with Sections 2 and/or 3 or prevents the
    enforceability of either of those Sections, this License will
    immediately terminate and You must immediately discontinue any use of
    the Covered Code and destroy all copies of it that are in your
    possession or control.
    
    13.6 Dispute Resolution. Any litigation or other dispute resolution
    between You and Apple relating to this License shall take place in the
    Northern District of California, and You and Apple hereby consent to
    the personal jurisdiction of, and venue in, the state and federal
    courts within that District with respect to this License. The
    application of the United Nations Convention on Contracts for the
    International Sale of Goods is expressly excluded.
    
    13.7 Entire Agreement; Governing Law. This License constitutes the
    entire agreement between the parties with respect to the subject
    matter hereof. This License shall be governed by the laws of the
    United States and the State of California, except that body of
    California law concerning conflicts of law.
    
    Where You are located in the province of Quebec, Canada, the following
    clause applies: The parties hereby confirm that they have requested
    that this License and all related documents be drafted in English. Les
    parties ont exige que le present contrat et tous les documents
    connexes soient rediges en anglais.
    
    EXHIBIT A.
    
    "Portions Copyright (c) 1999-2003 Apple Computer, Inc. All Rights
    Reserved.
    
    This file contains Original Code and/or Modifications of Original Code
    as defined in and that are subject to the Apple Public Source License
    Version 2.0 (the 'License'). You may not use this file except in
    compliance with the License. Please obtain a copy of the License at
    <http://www.opensource.apple.com/apsl/> and read it before using this
    file.
    
    The Original Code and all software distributed under the License are
    distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
    EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
    INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
    Please see the License for the specific language governing rights and
    limitations under the License."
    
[/code]

## About

No description, website, or topics provided.

License

[Activity](</opensource-apple/dyld/activity>)

### Stars

**662** stars

### Watchers

**27** watching

### Forks

[**133** forks](</opensource-apple/dyld/forks>)

[Report repository](</contact/report-content?content_url=https%3A%2F%2Fgithub.com%2Fopensource-apple%2Fdyld&report=opensource-apple+%28user%29>)

## Releases

## Packages

## Used by

## Contributors

## Languages

## Footer

[ ](<https://github.com>) © 2026 GitHub, Inc. 

### Footer navigation

  * [Terms](<https://docs.github.com/site-policy/github-terms/github-terms-of-service>)
  * [Privacy](<https://docs.github.com/site-policy/privacy-policies/github-privacy-statement>)
  * [Security](<https://github.com/security>)
  * [Status](<https://www.githubstatus.com/>)
  * [Community](<https://github.community/>)
  * [Docs](<https://docs.github.com/>)
  * [Contact](<https://support.github.com?tags=dotcom-footer>)
  * Manage cookies 
  * Do not share my personal information 



You can’t perform that action at this time. 

 
  *[v]: View this template
  *[t]: Discuss this template
  *[e]: Edit this template
