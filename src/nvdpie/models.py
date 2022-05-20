from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field, confloat, constr

# *******************************************************************
# *                           CVE MODEL                             *
# *******************************************************************
class CVEDataMeta(BaseModel):
    ID: str
    ASSIGNER: str
    STATE: Optional[str]


class LangString(BaseModel):
    lang: str
    value: str


class ProblemtypeDatum(BaseModel):
    description: List[LangString]


class Problemtype(BaseModel):
    problemtype_data: List[ProblemtypeDatum]


class Reference(BaseModel):
    url: str
    name: Optional[str] = None
    refsource: Optional[str] = None
    tags: Optional[List[str]] = None


class References(BaseModel):
    reference_data: List[Reference]


class Description(BaseModel):
    description_data: List[LangString]


class Cve(BaseModel):
    data_type: str
    data_format: str
    data_version: str
    CVE_data_meta: CVEDataMeta
    problemtype: Problemtype
    references: References
    description: Description


# *******************************************************************
# *                    Configurations MODEL                         *
# *******************************************************************
class CpeName(BaseModel):
    cpe22Uri: Optional[str] = None
    cpe23Uri: str
    lastModifiedDate: Optional[str] = None


class CpeMatch(BaseModel):
    vulnerable: bool
    cpe22Uri: Optional[str] = None
    cpe23Uri: str
    versionStartExcluding: Optional[str] = None
    versionStartIncluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    cpe_name: Optional[List[CpeName]] = None


class Node(BaseModel):
    operator: Optional[str] = None
    negate: Optional[bool] = None
    children: Optional[List[Node]] = None
    cpe_match: Optional[List[CpeMatch]] = None


class Configurations(BaseModel):
    CVE_data_version: str
    nodes: Optional[List[Node]] = None


# *******************************************************************
# *                        Impact MODEL                             *
# *******************************************************************
class AttackVectorType(Enum):
    NETWORK = 'NETWORK'
    ADJACENT_NETWORK = 'ADJACENT_NETWORK'
    LOCAL = 'LOCAL'
    PHYSICAL = 'PHYSICAL'


class ModifiedAttackVectorType(Enum):
    NETWORK = 'NETWORK'
    ADJACENT_NETWORK = 'ADJACENT_NETWORK'
    LOCAL = 'LOCAL'
    PHYSICAL = 'PHYSICAL'
    NOT_DEFINED = 'NOT_DEFINED'


class AttackComplexityType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'


class ModifiedAttackComplexityType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NOT_DEFINED = 'NOT_DEFINED'


class PrivilegesRequiredType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NONE = 'NONE'


class ModifiedPrivilegesRequiredType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NONE = 'NONE'
    NOT_DEFINED = 'NOT_DEFINED'


class UserInteractionType(Enum):
    NONE = 'NONE'
    REQUIRED = 'REQUIRED'


class ModifiedUserInteractionType(Enum):
    NONE = 'NONE'
    REQUIRED = 'REQUIRED'
    NOT_DEFINED = 'NOT_DEFINED'


class ScopeType(Enum):
    UNCHANGED = 'UNCHANGED'
    CHANGED = 'CHANGED'


class ModifiedScopeType(Enum):
    UNCHANGED = 'UNCHANGED'
    CHANGED = 'CHANGED'
    NOT_DEFINED = 'NOT_DEFINED'


class CiaType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'


class ModifiedCiaType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class ExploitCodeMaturityType(Enum):
    UNPROVEN = 'UNPROVEN'
    PROOF_OF_CONCEPT = 'PROOF_OF_CONCEPT'
    FUNCTIONAL = 'FUNCTIONAL'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class RemediationLevelType(Enum):
    OFFICIAL_FIX = 'OFFICIAL_FIX'
    TEMPORARY_FIX = 'TEMPORARY_FIX'
    WORKAROUND = 'WORKAROUND'
    UNAVAILABLE = 'UNAVAILABLE'
    NOT_DEFINED = 'NOT_DEFINED'


class ConfidenceType(Enum):
    UNKNOWN = 'UNKNOWN'
    REASONABLE = 'REASONABLE'
    CONFIRMED = 'CONFIRMED'
    NOT_DEFINED = 'NOT_DEFINED'


class CiaRequirementType(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class SeverityType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


class AccessVectorType(Enum):
    NETWORK = 'NETWORK'
    ADJACENT_NETWORK = 'ADJACENT_NETWORK'
    LOCAL = 'LOCAL'


class AccessComplexityType(Enum):
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'


class AuthenticationType(Enum):
    MULTIPLE = 'MULTIPLE'
    SINGLE = 'SINGLE'
    NONE = 'NONE'


class CiaTypeModel(Enum):
    NONE = 'NONE'
    PARTIAL = 'PARTIAL'
    COMPLETE = 'COMPLETE'


class ExploitabilityType(Enum):
    UNPROVEN = 'UNPROVEN'
    PROOF_OF_CONCEPT = 'PROOF_OF_CONCEPT'
    FUNCTIONAL = 'FUNCTIONAL'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class RemediationLevelTypeModel(Enum):
    OFFICIAL_FIX = 'OFFICIAL_FIX'
    TEMPORARY_FIX = 'TEMPORARY_FIX'
    WORKAROUND = 'WORKAROUND'
    UNAVAILABLE = 'UNAVAILABLE'
    NOT_DEFINED = 'NOT_DEFINED'


class ReportConfidenceType(Enum):
    UNCONFIRMED = 'UNCONFIRMED'
    UNCORROBORATED = 'UNCORROBORATED'
    CONFIRMED = 'CONFIRMED'
    NOT_DEFINED = 'NOT_DEFINED'


class CollateralDamagePotentialType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    LOW_MEDIUM = 'LOW_MEDIUM'
    MEDIUM_HIGH = 'MEDIUM_HIGH'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class TargetDistributionType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class CiaRequirementTypeModel(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class Version(Enum):
    field_3_0 = '3.0'
    field_3_1 = '3.1'
    field_2_0 = '2.0'


class Subscore(BaseModel):
    __root__: confloat(ge=0.0, le=10.0) = Field(..., description='CVSS subscore.')


class CvssV3(BaseModel):
    version: Version = Field(..., description='CVSS Version')
    baseScore: confloat(ge=0.0, le=10.0)
    baseSeverity: SeverityType
    vectorString: constr(
        regex=r'^CVSS:3.[01]/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$'
    )
    attackVector: Optional[AttackVectorType] = None
    attackComplexity: Optional[AttackComplexityType] = None
    privilegesRequired: Optional[PrivilegesRequiredType] = None
    userInteraction: Optional[UserInteractionType] = None
    scope: Optional[ScopeType] = None
    confidentialityImpact: Optional[CiaType] = None
    integrityImpact: Optional[CiaType] = None
    availabilityImpact: Optional[CiaType] = None
    exploitCodeMaturity: Optional[ExploitCodeMaturityType] = None
    remediationLevel: Optional[RemediationLevelType] = None
    reportConfidence: Optional[ConfidenceType] = None
    temporalScore: Optional[ScoreType] = None
    temporalSeverity: Optional[SeverityType] = None
    confidentialityRequirement: Optional[CiaRequirementType] = None
    integrityRequirement: Optional[CiaRequirementType] = None
    availabilityRequirement: Optional[CiaRequirementType] = None
    modifiedAttackVector: Optional[ModifiedAttackVectorType] = None
    modifiedAttackComplexity: Optional[ModifiedAttackComplexityType] = None
    modifiedPrivilegesRequired: Optional[ModifiedPrivilegesRequiredType] = None
    modifiedUserInteraction: Optional[ModifiedUserInteractionType] = None
    modifiedScope: Optional[ModifiedScopeType] = None
    modifiedConfidentialityImpact: Optional[ModifiedCiaType] = None
    modifiedIntegrityImpact: Optional[ModifiedCiaType] = None
    modifiedAvailabilityImpact: Optional[ModifiedCiaType] = None
    environmentalScore: Optional[ScoreType] = None
    environmentalSeverity: Optional[SeverityType] = None


class CvssV2(BaseModel):
    version: Version = Field(..., description='CVSS Version')
    baseScore: confloat(ge=0.0, le=10.0)
    vectorString: constr(
        regex=r'^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))$'
    )
    accessVector: Optional[AccessVectorType] = None
    accessComplexity: Optional[AccessComplexityType] = None
    authentication: Optional[AuthenticationType] = None
    confidentialityImpact: Optional[CiaTypeModel] = None
    integrityImpact: Optional[CiaTypeModel] = None
    availabilityImpact: Optional[CiaTypeModel] = None
    exploitability: Optional[ExploitabilityType] = None
    remediationLevel: Optional[RemediationLevelTypeModel] = None
    reportConfidence: Optional[ReportConfidenceType] = None
    temporalScore: Optional[ScoreTypeModel] = None
    collateralDamagePotential: Optional[CollateralDamagePotentialType] = None
    targetDistribution: Optional[TargetDistributionType] = None
    confidentialityRequirement: Optional[CiaRequirementTypeModel] = None
    integrityRequirement: Optional[CiaRequirementTypeModel] = None
    availabilityRequirement: Optional[CiaRequirementTypeModel] = None
    environmentalScore: Optional[ScoreTypeModel] = None


class BaseMetricV3(BaseModel):
    cvssV3: Optional[CvssV3] = None
    exploitabilityScore: Optional[Subscore] = None
    impactScore: Optional[Subscore] = None


class BaseMetricV2(BaseModel):
    cvssV2: Optional[CvssV2] = None
    severity: Optional[str] = None
    exploitabilityScore: Optional[Subscore] = None
    impactScore: Optional[Subscore] = None
    acInsufInfo: Optional[bool] = None
    obtainAllPrivilege: Optional[bool] = None
    obtainUserPrivilege: Optional[bool] = None
    obtainOtherPrivilege: Optional[bool] = None
    userInteractionRequired: Optional[bool] = None


class Impact(BaseModel):
    baseMetricV3: Optional[BaseMetricV3] = Field(None, description='CVSS V3.x score.')
    baseMetricV2: Optional[BaseMetricV2] = Field(None, description='CVSS V2.0 score.')


# *******************************************************************
# *                  Response and Result MODELS                     *
# *******************************************************************
class CVEItem(BaseModel):
    cve: Cve
    configurations: Optional[Configurations]
    impact: Optional[Impact]
    publishedDate: Optional[str]
    lastModifiedDate: Optional[str]


class Title(BaseModel):
    title: str
    lang: str


class CPEItem(BaseModel):
    deprecated: bool
    cpe23Uri: str
    lastModifiedDate: str
    titles: List[Title]
    refs: List[str]
    deprecatedBy: List[str]
    vulnerabilities: List[str]


class CpeResult(BaseModel):
    dataType: str
    feedVersion: str
    cpeCount: int
    feedTimestamp: str
    cpes: List[CPEItem]


class CveResult(BaseModel):
    CVE_data_type: str
    CVE_data_format: str
    CVE_data_version: str
    CVE_data_timestamp: str
    CVE_Items: List[CVEItem]


class Response(BaseModel):
    resultsPerPage: int
    startIndex: int
    totalResults: int
    result: Union[CveResult, CpeResult]
