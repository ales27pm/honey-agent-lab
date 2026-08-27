# Hugging Face Space Demo

A safe Gradio demo is available at the repository root via `app.py`.

## Safety posture

- simulation only;
- no secrets;
- no external agent connections;
- no network scanning;
- no credential collection;
- no live exploitation.

## Space settings

```text
SDK: Gradio
Entry point: app.py
```

## Demo behavior

The UI lets a user choose one synthetic scenario and returns:

- final risk score;
- policy action;
- controls;
- full JSON trace.
