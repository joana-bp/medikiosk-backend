from typing import Annotated, Literal, Optional
from pydantic import AliasChoices, BaseModel, BeforeValidator, EmailStr, Field, StringConstraints

Pw = Field(min_length=8, max_length=72)
# A staff username: 3-30 characters, letters, digits, dot, dash, underscore; stored in lower case. No "@", so a username
# can never be mistaken for an email address when someone signs in.
Username = Annotated[str, BeforeValidator(lambda v: v.strip().lower() if isinstance(v, str) else v),    # tidy first, then check
                     StringConstraints(min_length=3, max_length=30, pattern=r"^[a-z0-9][a-z0-9._-]*$")]


class SignInIn(BaseModel):
    """Staff and patients sign in with either their email or their username. The old `email` key still works."""
    identifier: str = Field(min_length=1, max_length=254, validation_alias=AliasChoices("identifier", "email", "username"))
    password: str = Field(min_length=1, max_length=72)


class PatientIn(BaseModel):
    firstName: str = Field(min_length=1, max_length=60)
    middleName: str = Field(default="", max_length=60)
    lastName: str = Field(min_length=1, max_length=60)
    address: str = Field(default="", max_length=200)
    birthday: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$", validation_alias=AliasChoices("birthday", "dob"))
    sex: Optional[str] = Field(default=None, max_length=20, validation_alias=AliasChoices("sex", "gender"))
    bloodType: Optional[str] = Field(default=None, max_length=5)
    email: EmailStr
    username: Username                # required for a new patient (mobile sign-up and staff registering one)
    password: str = Pw


class PatientPatch(BaseModel):
    firstName: Optional[str] = Field(default=None, min_length=1, max_length=60)
    middleName: Optional[str] = Field(default=None, max_length=60)
    lastName: Optional[str] = Field(default=None, min_length=1, max_length=60)
    address: Optional[str] = Field(default=None, max_length=200)
    birthday: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$", validation_alias=AliasChoices("birthday", "dob"))
    sex: Optional[str] = Field(default=None, max_length=20, validation_alias=AliasChoices("sex", "gender"))
    bloodType: Optional[str] = Field(default=None, max_length=5)
    email: Optional[EmailStr] = None
    username: Optional[Username] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=72)


class QrLoginIn(BaseModel):
    qrToken: str = Field(min_length=1, max_length=100)


class StaffIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    username: Optional[Username] = None
    clinic: str = Field(default="", max_length=100)
    accessRole: Literal["clinic_staff", "admin", "super_admin"] = "clinic_staff"   # what the account may do (the only role field)


class StaffPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    email: Optional[EmailStr] = None
    username: Optional[Username] = None
    clinic: Optional[str] = Field(default=None, max_length=100)
    status: Optional[str] = Field(default=None, max_length=20)


class PasswordChange(BaseModel):
    currentPassword: str = Field(min_length=1, max_length=72)
    newPassword: str = Pw


class KioskIn(BaseModel):
    id: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,40}$")
    name: str = Field(min_length=1, max_length=100)
    clinic: str = Field(default="", max_length=100)


class KioskPatch(BaseModel):
    status: Literal["Online", "Idle", "Maintenance", "Deactivated"]


class StatusIn(BaseModel):
    status: Literal["waiting", "in_progress", "done"]


class OverrideIn(BaseModel):
    tier: Literal["Normal", "Low", "Medium", "High"]
    reason: str = Field(min_length=5, max_length=500)
    confirmLower: bool = False      # needed to go below the minimum tier set by critical values
