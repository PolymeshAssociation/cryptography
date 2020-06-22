pub enum Transaction {
    Transfer(Transfer),
    Fund(Fund),
    Create(Create),
}

pub struct Party {
    pub name: String,
    pub cheater: bool,
}

pub struct Transfer {
    pub id: u32,
    pub sender: Party,
    pub receiver: Party,
    pub receiver_approves: bool,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub amount: u32,
    pub ticker: String,
}

impl Transfer {
    pub fn send(&self) -> String {
        String::from("list of arguments")
    }

    pub fn receive(&self) -> String {
        String::from("list of arguments")
    }

    pub fn mediate(&self) -> Option<String> {
        // since based  on cheating, the transaction might not get to the mediator
        Some(String::from("list of arguments"))
    }

    pub fn validate(&self) -> String {
        String::from("list of arguments")
    }
}

pub struct Create {
    pub id: u32,
    pub account_id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
}

fn cheater_flag(is_cheater: bool) -> String {
    if is_cheater {
        String::from("--cheater")
    } else {
        String::from("")
    }
}

//type StepFunc = &dyn Fn() -> String;
//
//impl Create {
//    pub fn create_account(&self) -> StepFunc {
//        &|| {
//            format!(
//                "mercat-account create --account-id {} --ticker {} --user {} {}",
//                self.account_id,
//                self.ticker,
//                self.owner.name,
//                cheater_flag(self.owner.cheater)
//            )
//        }
//    }
//
//    pub fn validate(&self) -> StepFunc {
//        &|| String::from("list of arguments")
//    }
//
//    pub fn order(&self) -> Vec<StepFunc> {
//        vec![self.create_account(), self.validate()]
//    }
//}

pub struct Fund {
    pub id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
    pub amount: u32,
}

pub enum Mode {
    Sequence { repeat: u32, steps: Vec<Mode> },
    Concurrent { repeat: u32, steps: Vec<Mode> },
    Transaction(Transaction),
}
