import Alert from "@cloudscape-design/components/alert";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import RadioGroup from "@cloudscape-design/components/radio-group";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Textarea from "@cloudscape-design/components/textarea";
import { ProfileMultiSelect, ProfileSingleSelect, type MultiOption, type SelectOption } from "./ProfileSelect";

export type OperatingMode = "single" | "multi";
export type AuthMethod = "profiles" | "assume_role";

export interface AuthState {
  operatingMode: OperatingMode;
  authMethod: AuthMethod;
  profiles: MultiOption[];
  singleProfile: SelectOption | null;
  accountIds: string;
  roleName: string;
}

export const INITIAL_AUTH_STATE: AuthState = {
  operatingMode: "single",
  authMethod: "profiles",
  profiles: [],
  singleProfile: null,
  accountIds: "",
  roleName: "",
};

/** Parse the account IDs textarea into a clean array. */
export function parseAccountIds(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

interface Props {
  state: AuthState;
  onChange: (state: AuthState) => void;
  disabled?: boolean;
  /** "multi" renders a multi-profile picker (Policy Analysis, IAM Fed). "single" renders a single-profile dropdown (IdC). */
  profileMode?: "multi" | "single";
}

/**
 * Shared operating-mode + authentication method selector.
 *
 * - Single account: uses the default AWS credential chain, no extra inputs.
 * - Multi-account: choose between named profiles or assume-role with account IDs.
 */
export function AuthMethodSelect({ state, onChange, disabled, profileMode = "multi" }: Props) {
  const update = (partial: Partial<AuthState>) => onChange({ ...state, ...partial });

  return (
    <SpaceBetween size="m">
      <FormField
        label="Operating mode"
        description="Choose whether to target a single account or multiple accounts."
      >
        <RadioGroup
          value={state.operatingMode}
          onChange={({ detail }) => update({ operatingMode: detail.value as OperatingMode })}
          items={[
            {
              value: "single",
              label: "Single account",
              description:
                "Operate against one account using your default AWS credential chain.",
              disabled,
            },
            {
              value: "multi",
              label: "Multi-account",
              description:
                "Operate against multiple accounts using named profiles or cross-account role assumption.",
              disabled,
            },
          ]}
        />
      </FormField>

      {state.operatingMode === "single" ? (
        <Alert type="info">
          Operations will use your <b>default AWS credentials</b> (environment variables,
          default profile, or instance metadata). Ensure these credentials have the
          necessary read permissions for the target account.
        </Alert>
      ) : (
        <>
          <FormField
            label="Account authentication"
            description="Choose how the target accounts are authenticated."
          >
            <RadioGroup
              value={state.authMethod}
              onChange={({ detail }) => update({ authMethod: detail.value as AuthMethod })}
              items={[
                {
                  value: "profiles",
                  label: "AWS credential profiles",
                  description:
                    profileMode === "multi"
                      ? "Use one or more local named profiles. Each is treated as its own account."
                      : "Use a local named profile for the target account.",
                  disabled,
                },
                {
                  value: "assume_role",
                  label: "Assume a role across accounts",
                  description:
                    "Provide account IDs and a role name. Your default credentials perform the AssumeRole calls. "
                    + "Your default credentials must have permission to call sts:AssumeRole for the specified role in each target account.",
                  disabled,
                },
              ]}
            />
          </FormField>

          {state.authMethod === "profiles" ? (
            profileMode === "multi" ? (
              <FormField
                label="AWS profiles"
                description="One or more profiles to use. Each is scanned as its own account, in parallel."
              >
                <ProfileMultiSelect
                  selected={state.profiles}
                  onChange={(profiles) => update({ profiles })}
                />
              </FormField>
            ) : (
              <FormField label="AWS profile">
                <ProfileSingleSelect
                  selected={state.singleProfile}
                  onChange={(singleProfile) => update({ singleProfile })}
                />
              </FormField>
            )
          ) : (
            <>
              <FormField
                label="Account IDs"
                description="Comma- or newline-separated 12-digit account IDs."
              >
                <Textarea
                  value={state.accountIds}
                  onChange={({ detail }) => update({ accountIds: detail.value })}
                  placeholder={"111111111111\n222222222222"}
                  rows={4}
                  disabled={disabled}
                />
              </FormField>
              <FormField
                label="Role name"
                description="Name (not ARN) of the role to assume in each account."
              >
                <Input
                  value={state.roleName}
                  onChange={({ detail }) => update({ roleName: detail.value })}
                  placeholder="OrganizationAccountAccessRole"
                  disabled={disabled}
                />
              </FormField>
            </>
          )}
        </>
      )}
    </SpaceBetween>
  );
}
