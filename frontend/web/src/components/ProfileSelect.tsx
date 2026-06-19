import { useEffect, useState } from "react";
import Multiselect, { MultiselectProps } from "@cloudscape-design/components/multiselect";
import Select, { SelectProps } from "@cloudscape-design/components/select";
import { api } from "../api/client";

// Public option types from Cloudscape. Both are structurally a { label, value }.
export type SelectOption = SelectProps.Option;
export type MultiOption = MultiselectProps.Option;

function useProfiles() {
  const [profiles, setProfiles] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch((e) => setError(e.message));
  }, []);

  return { profiles, error };
}

/** Multi-profile selector — used by Policy Analysis (one or more accounts). */
export function ProfileMultiSelect(props: {
  selected: MultiOption[];
  onChange: (selected: MultiOption[]) => void;
}) {
  const { profiles, error } = useProfiles();
  return (
    <Multiselect
      selectedOptions={props.selected}
      onChange={({ detail }) => props.onChange([...detail.selectedOptions])}
      options={profiles.map((p) => ({ label: p, value: p }))}
      placeholder={error ? "Could not load profiles" : "Choose one or more AWS profiles"}
      empty={error ?? "No profiles found in your AWS config"}
      filteringType="auto"
    />
  );
}

/** Single-profile selector — used by IdC (management / delegated admin). */
export function ProfileSingleSelect(props: {
  selected: SelectOption | null;
  onChange: (selected: SelectOption | null) => void;
}) {
  const { profiles, error } = useProfiles();
  return (
    <Select
      selectedOption={props.selected}
      onChange={({ detail }) => props.onChange(detail.selectedOption)}
      options={profiles.map((p) => ({ label: p, value: p }))}
      placeholder={error ? "Could not load profiles" : "Choose an AWS profile"}
      empty={error ?? "No profiles found in your AWS config"}
      filteringType="auto"
    />
  );
}
