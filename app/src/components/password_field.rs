use crate::infra::{
    api::HostService,
    common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::Result;
use std::time::Duration;
use yew::{
    html,
    services::{
        timeout::{TimeoutService, TimeoutTask},
        ConsoleService,
    },
    Callback, Component, ComponentLink, InputData, Properties,
};
use yew_form::{Field, Form, Model};

pub enum PasswordFieldMsg {
    OnInput(InputData),
    OnInputIdle,
    PasswordCheckResult(Result<Option<bool>>),
}

#[derive(PartialEq)]
pub enum PasswordState {
    // Whether the password was found in a leak.
    Checked(bool),
    NotSupported,
    Loading,
    Typing,
}

pub struct PasswordField<FormModel: Model> {
    common: CommonComponentParts<Self>,
    timeout_task: Option<TimeoutTask>,
    password: String,
    is_password_good: PasswordState,
}

impl<FormModel: Model> CommonComponent<PasswordField<FormModel>> for PasswordField<FormModel> {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> anyhow::Result<bool> {
        match msg {
            PasswordFieldMsg::OnInput(data) => {
                ConsoleService::log("OnInput");
                self.password = data.value;
                if self.is_password_good != PasswordState::NotSupported {
                    self.is_password_good = PasswordState::Typing;
                    if self.password.len() >= 8 {
                        self.timeout_task = Some(TimeoutService::spawn(
                            Duration::from_millis(500),
                            self.common.callback(|_| PasswordFieldMsg::OnInputIdle),
                        ));
                    }
                }
            }
            PasswordFieldMsg::PasswordCheckResult(result) => {
                ConsoleService::log("PasswordCheckResult");
                self.common.cancel_task();
                self.timeout_task = None;
                // If there's an error from the backend, don't retry.
                self.is_password_good = PasswordState::NotSupported;
                match result? {
                    None => self.is_password_good = PasswordState::NotSupported,
                    Some(check) => self.is_password_good = PasswordState::Checked(check),
                }
            }
            PasswordFieldMsg::OnInputIdle => {
                ConsoleService::log("OnInputIdle");
                self.timeout_task = None;
                if self.is_password_good != PasswordState::NotSupported {
                    self.is_password_good = PasswordState::Loading;
                    self.common.call_backend(
                        HostService::check_password_haveibeenpwned,
                        &self.password,
                        PasswordFieldMsg::PasswordCheckResult,
                    )?;
                }
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<PasswordField<FormModel>> {
        &mut self.common
    }
}

#[derive(Properties, PartialEq, Clone)]
pub struct PasswordFieldProperties<FormModel: Model> {
    pub field_name: String,
    pub form: Form<FormModel>,
    #[prop_or_else(|| { "form-control".to_owned() })]
    pub class: String,
    #[prop_or_else(|| { "is-invalid".to_owned() })]
    pub class_invalid: String,
    #[prop_or_else(|| { "is-valid".to_owned() })]
    pub class_valid: String,
    #[prop_or_else(Callback::noop)]
    pub oninput: Callback<InputData>,
}

impl<FormModel: Model> Component for PasswordField<FormModel> {
    type Message = PasswordFieldMsg;
    type Properties = PasswordFieldProperties<FormModel>;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(props, link),
            timeout_task: None,
            password: String::new(),
            is_password_good: PasswordState::Typing,
        }
    }

    fn update(&mut self, msg: Self::Message) -> yew::ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, _props: Self::Properties) -> yew::ShouldRender {
        false
    }

    fn view(&self) -> yew::Html {
        html! {
          <div>
            <Field<FormModel>
                autocomplete={"new-password"}
                input_type={"password"}
                field_name={self.common.field_name.clone()}
                form={self.common.form.clone()}
                class={self.common.class.clone()}
                class_invalid={self.common.class_invalid.clone()}
                class_valid={self.common.class_valid.clone()}
                oninput={self.common.callback(PasswordFieldMsg::OnInput)} />
            {
                match self.is_password_good {
                    PasswordState::Checked(true) => html! { <i class="bi bi-x"></i> },
                    PasswordState::Checked(false) => html! { <i class="bi bi-check"></i> },
                    PasswordState::NotSupported | PasswordState::Typing => html!{},
                    PasswordState::Loading =>
                        html! {
                          <div class="spinner-border spinner-border-sm" role="status">
                            <span class="sr-only">{"Loading..."}</span>
                          </div>
                        },
                }
            }
          </div>
        }
    }
}
