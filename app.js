//importing all important modules
const express = require("express");
const app = express();
const csrf = require("tiny-csrf");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const flash = require("connect-flash");
const LocalStratergy = require("passport-local");
const saltRounds = 10;
//models
const { ModelAdmin, model_election, model_questions, model_option, model_voter } = require("./models");
//using the view engine ejs
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
//using all the modules mentioned above
app.set("views", path.join(__dirname, "views"));
app.use(flash());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("This is some secret string"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));

//used for creating a session
app.use(
  session({
    secret: "my-super-secret-key-2837428907583420",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use((request, response, next) => {
  response.locals.messages = request.flash();
  next();
});

app.use(passport.initialize());
app.use(passport.session());

//voter authentication
passport.use(
  "voter_local",
  new LocalStratergy(
    {
      usernameField: "voter_id",
      passwordField: "password",
    },
    function (username, password, done) {
      model_voter.findOne({ where: { voter_id: username } })
        .then(async (user) => {
          const results = await bcrypt.compare(password, user.password);
          if (results) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Please Enter Correct Password" });
          }
        })
        .catch((error) => {
          return done(null, false, { message: "Please Enter Correct Voter ID" });
        });
    }
  )
);

//admin authentication
passport.use(
  "admin_local",
  new LocalStratergy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (username, password, done) {
      ModelAdmin.findOne({ where: { email: username } })
        .then(async (user) => {
          const results = await bcrypt.compare(password, user.password);
          if (results) {
            return done(null, user);
          } else {
            done(null, false, { message: "Please Enter Correct Password" });
          }
        })
        .catch((error) => {
          console.log(error);
          return done(null, false, { message: "Please Enter Correct Email Address" });
        });
    }
  )
);



passport.serializeUser((user, done) => {
  done(null, { id: user.id, role: user.role });
});
passport.deserializeUser((id, done) => {
  if (id.role === "admin") {
    ModelAdmin.findByPk(id.id)
      .then((user1) => {
        done(null, user1);
      })
      .catch((error1) => {
        done(error1, null);
      });
  } else if (id.role === "voter") {
    model_voter.findByPk(id.id)
      .then((user1) => {
        done(null, user1);
      })
      .catch((error1) => {
        done(error1, null);
      });
  }
});



//first (or) main Page
app.get("/", async function(req, res){
  if (req.user) {
    console.log(req.user);
    if (req.user.role === "admin") {
      return res.redirect("/elections");
    } else if (req.user.role === "voter") {
      req.logout((err1) => {
        if (err1) {
          return res.json(err1);
        }
        res.redirect("/");
      });
    }
  } else {
    res.render("index", {
      title: "Online Voting Platform",
      csrfToken: req.csrfToken(),
    });
  }
});

//main page for elections to perform admin operations
app.get("/elections",
  connectEnsureLogin.ensureLoggedIn(),async function (request1, response1) {
    if (request1.user.role === "admin") {
      let loggedInUser = request1.user.first_name + " " + request1.user.last_name;
      try {
        const elections = await model_election.getelections(request1.user.id);
        if (request1.accepts("html")) {
          response1.render("elections", {
            title: "Online E-Voting Platform",userName: loggedInUser,elections,
          });
        } else {
          return response1.json({elections,});
        }
      } catch (error3) {
        console.log(error3);
        return response1.status(422).json(error3);
      }
    } else if (request1.user.role === "voter") {
      return response1.redirect("/");
    }
  }
);

//SignUp
app.get("/signup", function(request2, response2) {
  response2.render("signup", {title: "create an admin account",csrfToken: request2.csrfToken(),});
});

//page used to create admin account
app.post("/admin", async function(req, res) {
  if (!req.body.firstName) {
    req.flash("error", "First Name is Missing !");
    return res.redirect("/signup");
  }
  if (!req.body.email) {
    req.flash("error", "Email ID is Missing !");
    return res.redirect("/signup");
  }
  if (!req.body.password) {
    req.flash("error", "Password is Missing !");
    return res.redirect("/signup"); 
  }
  if (req.body.password.length < 8) {
    req.flash("error", "Weak Password !! enter atleast 8 characters");
    return res.redirect("/signup");
  }
  const hashedPassword1 = await bcrypt.hash(req.body.password, saltRounds);
  try {
    const user = await ModelAdmin.create_a_new_admin({
      first_name: req.body.firstName,
      last_name: req.body.lastName,
      email: req.body.email,
      password: hashedPassword1,
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
        res.redirect("/");
      } else {
        res.redirect("/elections");
      }
    });
  } catch (error12) {
    req.flash("error", "Email Id not available please use other one !");
    return res.redirect("/signup");
  }
});

//admin login
app.get("/login", async function (request3, response3){
  if (request3.user) {
    return response3.redirect("/elections");
  }
  response3.render("login_page", {title: "Login to your account",csrfToken: request3.csrfToken(),});
});

//voter login
app.get("/e/:url/voter", async function (request4, response4) {
  response4.render("login_voter", {title: "Login in as Voter",url: request4.params.url,
    csrfToken: request4.csrfToken(),
  });
});

//starting the session for admin
app.post("/session",
  passport.authenticate("admin_local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (request1, response1) => {
    response1.redirect("/elections");
  }
);

//voter login post function
app.post("/e/:url/voter",
  passport.authenticate("voter_local", {
    failureRedirect: "/e/${request5.params.url}/voter",
    failureFlash: true,
  }),
  async function(request5, response5) {
    return response5.redirect(`/e/${request5.params.url}`);
  }
);

//New Election Being Created
app.post("/elections",connectEnsureLogin.ensureLoggedIn(),
  async function (request11, response11) {
    if (request11.user.role === "admin") {
      if (request11.body.electionName.length < 5) {
        request11.flash("error", "Ensure that election name length is greater than or equal to 5 characters!");
        return response11.redirect("/elections/create");
      }
      if (request11.body.url.length < 3) {
        request11.flash("error", "Ensure that length of url is greater than or equal to 3 characters");
        return response11.redirect("/elections/create");
      }
      if (
        request11.body.url.includes(" ") ||
        request11.body.url.includes("\t") ||
        request11.body.url.includes("\n")
      ) {
        request11.flash("error", "url must not contaion escape characters or spaces");
        return response11.redirect("/elections/create");
      }
      try {
        await model_election.addAnElection({
          election_name: request11.body.electionName,
          url: request11.body.url,
          admin_id: request11.user.id,
        });
        return response11.redirect("/elections");
      } catch (error) {
        request11.flash("error", "URL not available use any other one");
        return response11.redirect("/elections/create");
      }
    } else if (request11.user.role === "voter") {
      return response11.redirect("/");
    }
  }
);
//validate every field and create a model accordingly

//creating New election
app.get("/elections/create",
  connectEnsureLogin.ensureLoggedIn(),async function(request9, response9) {
    if (request9.user.role === "admin") {
      return response9.render("new_election_page", {
        title: "create an election",
        csrfToken: request9.csrfToken(),
      });
    } else if (request9.user.role === "voter") {
      return response9.redirect("/");
    }
  }
);


//This  is  the election page every information about a particular election is available here
app.get("/elections/:id",
  connectEnsureLogin.ensureLoggedIn(),async function (req, res) {
    if (req.user.role === "admin") {
      try {
        const election1 = await model_election.getElection(req.params.id);
        const numberOfQuestionsAre = await model_questions.getNumberOfQuestionss(
          req.params.id
        );
        const numberOfVotersAre = await model_voter.getNumberOfVoterss(req.params.id);
        return res.render("elections_page", {
          id: req.params.id,
          title: election1.election_name,
          url: election1.url,
          launch: election1.launch,
          nq: numberOfQuestionsAre,
          nv: numberOfVotersAre,
        });
      } catch (error2) {
        console.log(error2);
        return res.status(422).json(error2);
      }
    } else if (req.user.role === "voter") {
      return res.redirect("/");
    }
  }
);

//A page for creating and adding questions in the elections
app.get("/elections/:id/questions/create",
  connectEnsureLogin.ensureLoggedIn(),async function (request2, response1){
    if (request2.user.role === "admin") {
      try {
        const election3 = await model_election.getElection(request2.params.id);
        if (!election3.launch) {
          return response1.render("new_question_page", {
            id: request2.params.id,
            csrfToken: request2.csrfToken(),
          });
        } else {
          request2.flash("error", "can't edit while election is in launch mode");
          return response1.redirect(`/elections/${request2.params.id}/`);
        }
      } catch (error1) {
        console.log(error1);
        return response1.status(422).json(error1);
      }
    } else if (request2.user.role === "voter") {
      return response1.redirect("/");
    }
  }
);

//A page to manage questions i.e performing CRUD operations on the questions
app.get("/elections/:id/questions",
  connectEnsureLogin.ensureLoggedIn(),async function (request1, response) {
    if (request1.user.role === "admin") {
      try {
        const election2 = await model_election.getElection(request1.params.id);
        const questions2 = await model_questions.getQuestionss(request1.params.id);
        if (!election2.launch) {
          if (request1.accepts("html")) {
            return response.render("all_questions", {
              title: election2.electionName,
              id: request1.params.id,
              questions: questions2,
              csrfToken: request1.csrfToken(),
            });
          } else {
            return response.json({
              questions2,
            });
          }
        } else {
          request1.flash("error", "can't edit while election is in launch mode");
          return response.redirect(`/elections/${request1.params.id}/`);
        }
      } catch (error1) {
        console.log(error1);
        return response.status(422).json(error1);
      }
    } else if (request1.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

//a page for adding new questions
app.post("/elections/:id/questions/create",
  connectEnsureLogin.ensureLoggedIn(),async function (request3, response3){
    if (request3.user.role === "admin") {
      if (request3.body.questionName.length < 5) {
        request3.flash("error", "Ensure that length of question is greater than or equal to 5 characters");
        return response3.redirect(`/elections/${request3.params.id}/questions/create`);
      }
      try {
        const elections = await model_election.getElection(request3.params.id);
        if (elections.launch) {
          request3.flash("error", "can't edit while election is in launch mode");
          return response3.redirect(`/elections/${request3.params.id}/`);
        }
        const question = await model_questions.addAQuestion({
          question_name: request3.body.questionName,
          question_description: request3.body.description,
          election_id: request3.params.id,
        });
        return response3.redirect(`/elections/${request3.params.id}/questions/${question.id}`);
      } catch (error1) {
        console.log(error1);
        return response3.status(422).json(error1);
      }
    } else if (request3.user.role === "voter") {
      return response3.redirect("/");
    }
  }
);

//edit question page
//this the page where we can edit the questions
//admin can edit the questions here
//for a particular election
app.get("/elections/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),async function (request5, response5){
    if (request5.user.role === "admin") {
      try {
        const elections = await model_election.getElection(request5.params.electionID);
        if (elections.launch) {
          request5.flash("error", "can't edit while election is in launch mode");
          return response5.redirect(`/elections/${request5.params.id}/`);
        }
        const questions = await model_questions.getQuestion(request5.params.questionID);
        return response5.render("edit_question_page", {
          electionID: request5.params.electionID,
          questionID: request5.params.questionID,
          questionName: questions.question_name,
          description: questions.question_description,
          csrfToken: request5.csrfToken(),
        });
      } catch (error5) {
        console.log(error5);
        return response5.status(422).json(error5);
      }
    } else if (request5.user.role === "voter") {
      return response5.redirect("/");
    }
  }
);

//A page used for editing the question
app.put("/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),async function(request6, response6)  {
    if (request6.user.role === "admin") {
      if (request6.body.questionName.length < 5) {
        request6.flash("error", "Ensure that length of the question is greater than or equal to 5 characters");
        return response6.json({
          error: "Ensure that length of the question is greater than or equal to 5 characters",
        });
      }
      try {
        const updatedQuestionIs = await model_questions.updateAQuestion({
          question_name: request6.body.questionName,
          question_description: request6.body.description,
          id: request6.params.questionID,
        });
        return response6.json(updatedQuestionIs);
      } catch (error6) {
        console.log(error6);
        return response6.status(422).json(error6);
      }
    } else if (request6.user.role === "voter") {
      return response6.redirect("/");
    }
  }
);

//the route used for deleting a question
app.delete("/elections/:electionID/questions/:questionID",
  connectEnsureLogin.ensureLoggedIn(),async function(request7, response7) {
    if (request7.user.role === "admin") {
      try {
        //to get number of questions
        const numq = await model_questions.getNumberOfQuestionss(
          request7.params.electionID
        );
        //update here
        if (numq > 0) {
          //to delete a question
          const res1 = await model_questions.deleteAQuestion(request7.params.questionID);
          return response7.json({ success: res1 === 1 });
        } else {
          return response7.json({ success: false });
        }
      } catch (error7) {
        console.log(error7);
        return response7.status(422).json(error7);
      }
    } else if (request7.user.role === "voter") {
      return response7.redirect("/");
    }
  }
);

//a route for displaying the questions
app.get("/elections/:id/questions/:questionID",
  connectEnsureLogin.ensureLoggedIn(),async function(request8, response8)  {
    if (request8.user.role === "admin") {
      try {
        //we are retrieving questions, options and election
        //when the election is launched we cant edit the questions
        const questions = await model_questions.getQuestion(request8.params.questionID);
        const options = await model_option.getOptionss(request8.params.questionID);
        const election = await model_election.getElection(request8.params.id);
        if (election.launch) {
          request8.flash("error", "can't edit while election is in launch mode");
          return response8.redirect(`/elections/${request8.params.id}/`);
        }
        if (request8.accepts("html")) {
          response8.render("questions_page", {
            title: questions.question_name,
            description: questions.question_description,
            id: request8.params.id,
            questionID: request8.params.questionID,
            options,
            csrfToken: request8.csrfToken(),
          });
        } else {
          return response8.json({
            options,
          });
        }
      } catch (error8) {
        console.log(error8);
        return response8.status(422).json(error8);
      }
    } else if (request8.user.role === "voter") {
      return response8.redirect("/");
    }
  }
);

//a route used for adding options to a particular question
app.post("/elections/:id/questions/:questionID",
  connectEnsureLogin.ensureLoggedIn(),async function(request9, response9) {
    if (request9.user.role === "admin") {
      if (!request9.body.option) {
        request9.flash("error", "Enter atleast one option!");
        return response9.redirect(
          `/elections/${request9.params.id}/questions/${request9.params.questionID}`
        );
      }
      try {
        const election = await model_election.getElection(request9.params.id);
        if (election.launch) {
          request9.flash("error", "cant edit while election is in launch mode!");
          return response9.redirect(`/elections/${request9.params.id}/`);
        }
        await model_option.addAnOption({
          choice: request9.body.option,
          question_id: request9.params.questionID,
        });
        return response9.redirect(
          `/elections/${request9.params.id}/questions/${request9.params.questionID}`
        );
      } catch (error) {
        console.log(error);
        return response9.status(422).json(error);
      }
    } else if (request9.user.role === "voter") {
      return response9.redirect("/");
    }
  }
);

//a route for deleting option which can only be accessed by the admin
app.delete("/options/:optionID",
  connectEnsureLogin.ensureLoggedIn(),async function(request12, response12) {
    if (request12.user.role === "admin") {
      try {
        const res = await model_option.deleteAnOption(request12.params.optionID);
        return response12.json({ success: res === 1 });
      } catch (errora) {
        console.log(errora);
        return response12.status(422).json(errora);
      }
    } else if (request12.user.role === "voter") {
      return response12.redirect("/");
    }
  }
);

//edit option page
app.get("/elections/:electionID/questions/:questionID/options/:optionID/edit",
  connectEnsureLogin.ensureLoggedIn(),async function(requesta, responsea) {
    if (requesta.user.role === "admin") {
      try {
        const electiona = await model_election.getElection(requesta.params.electionID);
        if (electiona.launch) {
          requesta.flash("error", "can't edit while election is in launch mode!!!");
          return responsea.redirect(`/elections/${requesta.params.id}/`);
        }
        const optiona = await model_option.getOption(requesta.params.optionID);
        return responsea.render("edit_option_page", {
          option: optiona.choice,
          csrfToken: requesta.csrfToken(),
          electionID: requesta.params.electionID,
          questionID: requesta.params.questionID,
          optionID: requesta.params.optionID,
        });
      } catch (error) {
        console.log(error);
        return responsea.status(422).json(error);
      }
    } else if (requesta.user.role === "voter") {
      return responsea.redirect("/");
    }
  }
);




//a page used to update the options which can only be accessed by the admin
app.put("/options/:optionID/edit",
  connectEnsureLogin.ensureLoggedIn(),async function (requestb, responseb) {
    if (requestb.user.role === "admin") {
      if (!requestb.body.option) {
        requestb.flash("error", "please dont leave it empty");
        return responseb.json({
          error: "Please enter option",
        });
      }
      try {
        const updatedOptionsAre = await model_option.updateAnOption({
          id: requestb.params.optionID,
          choice: requestb.body.option,
        });
        return responseb.json(updatedOptionsAre);
      } catch (errorb) {
        console.log(errorb);
        return responseb.status(422).json(errorb);
      }
    } else if (requestb.user.role === "voter") {
      return responseb.redirect("/");
    }
  }
);



//add voter page
//this is the page where we can add voters
//create new voters
app.get("/elections/:electionID/voters/create",
  connectEnsureLogin.ensureLoggedIn(),async function(requeste, responsee) {
    if (requeste.user.role === "admin") {
      responsee.render("new_voters_page", {
        title: "Warning!!!",
        electionID: requeste.params.electionID,
        csrfToken: requeste.csrfToken(),
      });
    } else if (requeste.user.role === "voter") {
      return responsee.redirect("/");
    }
  }
);

//voter page
app.get("/elections/:electionID/voters",
  connectEnsureLogin.ensureLoggedIn(),async function(request9, response9) {
    if (request9.user.role === "admin") {
      try {
        const voters = await model_voter.gettVoters(request9.params.electionID);
        const elections = await model_election.getElection(request9.params.electionID);
        if (request9.accepts("html")) {
          return response9.render("voters_page", {
            title: elections.election_name,
            id: request9.params.electionID,
            voters,
            electionID: request9.params.electionID,
            csrfToken: request9.csrfToken(),
          });
        } else {
          return response9.json({voters,});
        }
      } catch (error9) {
        console.log(error9);
        return response9.status(422).json(error9);
      }
    } else if (request9.user.role === "voter") {
      return response9.redirect("/");
    }
  }
);


// a route used to add voters the admin can give username , password to add voters in the online voting system.
app.post("/elections/:electionID/voters/create",
  connectEnsureLogin.ensureLoggedIn(),async function(requestr, responser) {
    if (requestr.user.role === "admin") {
      if (!requestr.body.voterid) {
        requestr.flash("error", "Missing Voter ID");
        return responser.redirect(`/elections/${requestr.params.electionID}/voters/create`);
      }
      if (!requestr.body.password) {
        requestr.flash("error", "Missing Password of the voter");
        return responser.redirect(
          `/elections/${requestr.params.electionID}/voters/create`
        );
      }
      if (requestr.body.password.length < 6) {
        requestr.flash("error", "Ensure that length of password is greater than or equal to 8 characters");
        return responser.redirect(
          `/elections/${requestr.params.electionID}/voters/create`
        );
      }
      const hashedPassword1 = await bcrypt.hash(requestr.body.password, saltRounds);
      try {
        await model_voter.createAVoter({
          voter_id: requestr.body.voterid,
          password: hashedPassword1,
          election_id: requestr.params.electionID,
        });
        return responser.redirect(
          `/elections/${requestr.params.electionID}/voters`
        );
      } catch (errorr) {
        requestr.flash("error", "voter ID not available please use any other one");
        return responser.redirect(
          `/elections/${requestr.params.electionID}/voters/create`
        );
      }
    } else if (requestr.user.role === "voter") {
      return responser.redirect("/");
    }
  }
);


//a route used for deleting the voters
app.delete("/elections/:electionID/voters/:voterID",
  connectEnsureLogin.ensureLoggedIn(),async function(requestz, responsez) {
    if (requestz.user.role === "admin") {
      try {
        const res2 = await model_voter.deleteAVoter(requestz.params.voterID);
        return responsez.json({ success: res2 === 1 });
      } catch (errorz) {
        console.log(errorz);
        return responsez.status(422).json(errorz);
      }
    } else if (requestz.user.role === "voter") {
      return responsez.redirect("/");
    }
  }
);




// a route used the show the view of election
app.get("/elections/:electionID/preview",
  connectEnsureLogin.ensureLoggedIn(),async function (requestl, responsel) {
    if (requestl.user.role === "admin") {
      try {
        const election = await model_election.getElection(requestl.params.electionID);
        const questions = await model_questions.getQuestionss(
          requestl.params.electionID
        );
        let options = [];
        for (let question in questions) {
          const question_options = await model_option.getOptionss(
            questions[question].id
          );
          if (question_options.length < 2) {
            requestl.flash(
              "error","Make sure to please add atleast two options to the question below!!!"
            );
            requestl.flash(
              "error","Make sure there should be atleast two options in each question!!!"
            );
            return responsel.redirect(
              `/elections/${requestl.params.electionID}/questions/${questions[question].id}`
            );
          }
          options.push(question_options);
        }

        if (questions.length < 1) {
          requestl.flash(
            "error",
            "Make sure to please add atleast one question in the ballot!!!"
          );
          return responsel.redirect(`/elections/${requestl.params.electionID}/questions`);
        }

        return responsel.render("vote_preview_page", {
          title: election.election_name,
          electionID: requestl.params.electionID,
          questions,
          options,
          csrfToken: requestl.csrfToken(),
        });
      } catch (errorl) {
        console.log(errorl);
        return responsel.status(422).json(errorl);
      }
    } else if (requestl.user.role === "voter") {
      return responsel.redirect("/");
    }
  }
);


//a route for lauching the election the voters can access the link and vote
app.put("/elections/:electionID/launch",
  connectEnsureLogin.ensureLoggedIn(),async function (requestk, responsek) {
    if (requestk.user.role === "admin") {
      try {
        const launchedElection = await model_election.launchAnElection(
          requestk.params.electionID
        );
        return responsek.json(launchedElection);
      } catch (errork) {
        console.log(errork);
        return responsek.status(422).json(errork);
      }
    } else if (requestk.user.role === "voter") {
      return responsek.redirect("/");
    }
  }
);

//a live link which allows voters to vote
app.get("/e/:url/", async function (requestaa, responseaa){
  if (!requestaa.user) {
    requestaa.flash("error", "Ensure that you login before voting");
    return responseaa.redirect(`/e/${requestaa.params.url}/voter`);
  }
  try {
    const election = await model_election.getElectionurl(requestaa.params.url);
    if (requestaa.user.role === "voter") {
      if (election.launch) {
        const questions = await model_questions.getQuestionss(election.id);
        let options = [];
        for (let question in questions) {
          options.push(await model_option.getOptionss(questions[question].id));
        }
        return responseaa.render("vote_page", {
          title: election.election_name,
          electionID: election.id,
          questions,
          options,
          csrfToken: requestaa.csrfToken(),
        });
      } else {
        return responseaa.render("404_not_found");
      }
    } else if (requestaa.user.role === "admin") {
      requestaa.flash("error", "Since you are the admin , you cant vote for the election");
      requestaa.flash("error", "if you want to vote sign out as the admin");
      return responseaa.redirect(`/elections/${election.id}`);
    }
  } catch (erroraa) {
    console.log(erroraa);
    return responseaa.status(422).json(erroraa);
  }
});

//success page
app.get("/success",async function(req,res){
  res.render("success_page");
});

//results page
app.get("/results_page",async function(req,res){
  res.render("results_page");
});

//signout route
app.get("/signout", function (request6, response6, next){
  request6.logout((err1) => {
    if (err1) {
      return next(err1);
    }
    response6.redirect("/");
  });
});


module.exports = app;