{{- with secret "ssh/config/ca" -}}
{{ .Data.public_key }}
{{- end -}}
